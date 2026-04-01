"""Scan Kubernetes ConfigMaps and Secrets for potential secret leakage."""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import re

from kubernetes import client, config

# Timezone used for consistent report timestamps.
IST = timezone(timedelta(hours=5, minutes=30))
# Logical cluster identifier written into report metadata.
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "null-cluster-name")

# Namespaces to skip by default to reduce noise from system workloads.
DEFAULT_EXCLUDED_NAMESPACES = [
    ns.strip()
    for ns in os.getenv(
        "SECRET_SCANNER_EXCLUDE_NAMESPACES",
        "kube-system,kube-public,kube-node-lease",
    ).split(",")
    if ns.strip()
]

DEFAULT_INCLUDE_KINDS = {
    kind.strip().lower()
    for kind in os.getenv(
        "SECRET_SCANNER_INCLUDE_KINDS",
        "configmap,secret",
    ).split(",")
    if kind.strip()
}

# Sensitive-looking key fragments used for conservative key-name matching.
SUSPICIOUS_KEYWORDS = [
    kw.strip().lower()
    for kw in os.getenv(
        "SECRET_SCANNER_SUSPICIOUS_KEYWORDS",
        "password,passwd,pwd,secret,token,api_key,apikey,access_key,private_key,client_secret",
    ).split(",")
    if kw.strip()
]

# Known benign keys ignored to lower false positives.
ALLOWLIST_KEYS = {
    k.strip().lower()
    for k in os.getenv(
        "SECRET_SCANNER_KEY_ALLOWLIST",
        "tokenreviews,token_reviewer_jwt,audience,audiences,serviceaccount,service_account",
    ).split(",")
    if k.strip()
}

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SUPPORTED_KINDS = {"configmap", "secret"}

# High-confidence value signatures used in conservative mode.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b")
PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.IGNORECASE,
)


def get_time_now() -> str:
    return datetime.now(IST).isoformat()


def load_kube_config() -> None:
    """Load Kubernetes configuration (in-cluster or local)."""
    try:
        config.load_incluster_config()
        print("Loaded in-cluster kube config")
    except Exception:
        try:
            config.load_kube_config()
            print("Loaded local kube config")
        except Exception as exc:
            print(f"Failed to load Kubernetes configuration: {exc}")
            raise


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def _is_suspicious_key(key: Optional[str]) -> bool:
    if not key:
        return False
    normalized = _normalize_key(key)
    if normalized in ALLOWLIST_KEYS:
        return False
    return any(keyword in normalized for keyword in SUSPICIOUS_KEYWORDS)


def _match_strong_secret_signature(value: str) -> Optional[str]:
    if not value:
        return None
    if JWT_RE.search(value):
        return "jwt"
    if PEM_PRIVATE_KEY_RE.search(value):
        return "pem_private_key"
    if AWS_ACCESS_KEY_RE.search(value):
        return "aws_access_key_id"
    return None


def _mask_value(value: Optional[str]) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}...{s[-4:]}"


def _create_finding(
    *,
    severity: str,
    rule_id: str,
    message: str,
    namespace: str,
    kind: str,
    object_name: str,
    field_path: str,
    evidence: str = "",
    container: Optional[str] = None,
    recommendation: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "severity": severity,
        "rule_id": rule_id,
        "message": message,
        "namespace": namespace,
        "kind": kind,
        "object_name": object_name,
        "container": container,
        "field_path": field_path,
        "evidence_masked": _mask_value(evidence),
        "recommendation": recommendation
        or "Move secret material into Kubernetes Secret and reference via secretKeyRef.",
    }


def _scan_annotations_and_labels(
    *,
    metadata: Any,
    namespace: str,
    kind: str,
    object_name: str,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    annotations = getattr(metadata, "annotations", None) or {}
    labels = getattr(metadata, "labels", None) or {}

    for map_name, kvs in [("annotations", annotations), ("labels", labels)]:
        for key, val in kvs.items():
            key_str = str(key)
            value_str = str(val) if val is not None else ""

            if _is_suspicious_key(key_str):
                findings.append(
                    _create_finding(
                        severity="medium",
                        rule_id="suspicious-metadata-key",
                        message=f"Suspicious {map_name} key suggests secret data might be stored in metadata.",
                        namespace=namespace,
                        kind=kind,
                        object_name=object_name,
                        field_path=f"metadata.{map_name}.{key_str}",
                        evidence=value_str,
                        recommendation="Do not place secrets in labels/annotations.",
                    )
                )

            sig = _match_strong_secret_signature(value_str)
            if sig:
                findings.append(
                    _create_finding(
                        severity="high",
                        rule_id="metadata-contains-secret-signature",
                        message=f"{map_name.capitalize()} value matches strong secret signature ({sig}).",
                        namespace=namespace,
                        kind=kind,
                        object_name=object_name,
                        field_path=f"metadata.{map_name}.{key_str}",
                        evidence=value_str,
                    )
                )

    return findings


def _scan_configmap(cm: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    metadata = getattr(cm, "metadata", None)
    if not metadata or not metadata.name or not metadata.namespace:
        return findings

    namespace = metadata.namespace
    object_name = metadata.name

    findings.extend(
        _scan_annotations_and_labels(
            metadata=metadata,
            namespace=namespace,
            kind="ConfigMap",
            object_name=object_name,
        )
    )

    for map_name, data in [
        ("data", getattr(cm, "data", None) or {}),
        ("binaryData", getattr(cm, "binary_data", None) or {}),
    ]:
        for key, value in data.items():
            key_str = str(key)
            value_str = str(value) if value is not None else ""
            field_path = f"{map_name}.{key_str}"

            if _is_suspicious_key(key_str) and value_str:
                findings.append(
                    _create_finding(
                        severity="high",
                        rule_id="configmap-suspicious-key-with-value",
                        message="ConfigMap contains plaintext value under secret-like key.",
                        namespace=namespace,
                        kind="ConfigMap",
                        object_name=object_name,
                        field_path=field_path,
                        evidence=value_str,
                        recommendation="Move sensitive values from ConfigMap to Secret.",
                    )
                )

            signature = _match_strong_secret_signature(value_str)
            if signature:
                findings.append(
                    _create_finding(
                        severity="high",
                        rule_id="configmap-value-secret-signature",
                        message=f"ConfigMap value matches strong secret signature ({signature}).",
                        namespace=namespace,
                        kind="ConfigMap",
                        object_name=object_name,
                        field_path=field_path,
                        evidence=value_str,
                        recommendation="Move this value to Secret and rotate it if exposed.",
                    )
                )

    return findings


def _scan_secret_metadata(secret: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    metadata = getattr(secret, "metadata", None)
    if not metadata or not metadata.name or not metadata.namespace:
        return findings

    namespace = metadata.namespace
    object_name = metadata.name
    stype = getattr(secret, "type", None) or ""

    findings.extend(
        _scan_annotations_and_labels(
            metadata=metadata,
            namespace=namespace,
            kind="Secret",
            object_name=object_name,
        )
    )

    # Conservative metadata-only misuse signal:
    # suspicious key names inside stringData keys are plaintext at submission time.
    string_data = getattr(secret, "string_data", None) or {}
    for key, value in string_data.items():
        if _is_suspicious_key(str(key)) and value is not None:
            findings.append(
                _create_finding(
                    severity="high",
                    rule_id="secret-stringdata-suspicious-key",
                    message=(
                        "Secret has suspicious key under stringData; plaintext may be exposed in manifests or tooling history."
                    ),
                    namespace=namespace,
                    kind="Secret",
                    object_name=object_name,
                    field_path=f"stringData.{key}",
                    evidence=str(value),
                    recommendation="Avoid committing plaintext stringData in manifests; use secure secret delivery.",
                )
            )

    if _is_suspicious_key(object_name) and stype == "Opaque":
        findings.append(
            _create_finding(
                severity="low",
                rule_id="secret-name-indicates-sensitive-content",
                message="Secret name indicates sensitive content; verify strict access control and rotation policy.",
                namespace=namespace,
                kind="Secret",
                object_name=object_name,
                field_path="metadata.name",
                evidence=object_name,
                recommendation="Confirm least-privilege RBAC and rotation cadence for this secret.",
            )
        )

    return findings


def _append_findings_with_ids(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    indexed: List[Dict[str, Any]] = []
    for idx, finding in enumerate(findings, start=1):
        with_id = dict(finding)
        with_id["id"] = f"F-{idx:05d}"
        indexed.append(with_id)
    return indexed


def _build_summaries(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, int], Dict[str, int], List[Dict[str, Any]]]:
    summary_by_namespace: Dict[str, int] = {}
    summary_by_severity: Dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    object_summary: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for f in findings:
        namespace = f["namespace"]
        severity = f["severity"]
        kind = f["kind"]
        object_name = f["object_name"]

        summary_by_namespace[namespace] = summary_by_namespace.get(namespace, 0) + 1
        summary_by_severity[severity] = summary_by_severity.get(severity, 0) + 1

        key = (namespace, kind, object_name)
        if key not in object_summary:
            object_summary[key] = {
                "namespace": namespace,
                "kind": kind,
                "object_name": object_name,
                "total_findings": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "max_severity": "low",
            }

        object_summary[key]["total_findings"] += 1
        object_summary[key][severity] += 1
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[object_summary[key]["max_severity"]]:
            object_summary[key]["max_severity"] = severity

    object_risk_summary = sorted(
        object_summary.values(),
        key=lambda item: (
            -SEVERITY_ORDER[item["max_severity"]],
            -item["high"],
            -item["medium"],
            -item["total_findings"],
            item["namespace"],
            item["kind"],
            item["object_name"],
        ),
    )
    return summary_by_namespace, summary_by_severity, object_risk_summary


def scan_configmaps_and_secrets(
    *,
    exclude_namespaces: Optional[List[str]] = None,
    include_kinds: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Scan Kubernetes ConfigMaps and Secrets for likely secret leakage patterns."""
    load_kube_config()
    core_v1 = client.CoreV1Api()

    include = {k.lower() for k in (include_kinds or DEFAULT_INCLUDE_KINDS)}
    exclude_set = set(DEFAULT_EXCLUDED_NAMESPACES)
    exclude_set.update(ns.strip() for ns in (exclude_namespaces or []) if ns and ns.strip())

    findings: List[Dict[str, Any]] = []
    scan_errors: List[Dict[str, str]] = []
    object_scan_counts: Dict[str, int] = {
        "configmap": 0,
        "secret": 0,
    }

    unknown_kinds = sorted(include - SUPPORTED_KINDS)
    if unknown_kinds:
        print(f"Ignoring unsupported include kinds: {', '.join(unknown_kinds)}")

    print(f"Scanning kinds: {', '.join(sorted(include & SUPPORTED_KINDS))}")
    print(f"Excluding namespaces: {', '.join(sorted(exclude_set))}")

    # Scan ConfigMaps.
    if "configmap" in include:
        try:
            print("[1/2] Fetching ConfigMaps from all namespaces...")
            configmaps = core_v1.list_config_map_for_all_namespaces().items
            print(f"       Retrieved {len(configmaps)} configmaps, scanning...")
            for cm in configmaps:
                ns = cm.metadata.namespace
                if ns in exclude_set:
                    continue
                object_scan_counts["configmap"] += 1
                findings.extend(_scan_configmap(cm))
            print(f"       Scanned {object_scan_counts['configmap']} configmaps ({len(findings)} findings so far)")
        except Exception as exc:
            scan_errors.append({"kind": "configmap", "error": str(exc)})
            print(f"       FAILED to scan ConfigMaps: {exc}")

    # Scan Secrets (metadata-oriented checks).
    if "secret" in include:
        try:
            print("[2/2] Fetching Secrets from all namespaces...")
            secrets = core_v1.list_secret_for_all_namespaces().items
            print(f"       Retrieved {len(secrets)} secrets, scanning...")
            for sec in secrets:
                ns = sec.metadata.namespace
                if ns in exclude_set:
                    continue
                object_scan_counts["secret"] += 1
                findings.extend(_scan_secret_metadata(sec))
            print(f"       Scanned {object_scan_counts['secret']} secrets ({len(findings)} findings so far)")
        except Exception as exc:
            scan_errors.append({"kind": "secret", "error": str(exc)})
            print(f"       FAILED to scan Secrets: {exc}")

    print(f"All resource scans complete. Total findings: {len(findings)}")
    print("Building summaries...")
    findings_with_ids = _append_findings_with_ids(findings)
    summary_by_namespace, summary_by_severity, object_risk_summary = _build_summaries(findings_with_ids)

    result = {
        "timestamp": get_time_now(),
        "cluster_name": CLUSTER_NAME,
        "scanner_mode": "configmap_secret_only",
        "exclude_namespaces": sorted(exclude_set),
        "include_kinds": sorted(include),
        "objects_scanned": object_scan_counts,
        "total_findings": len(findings_with_ids),
        "summary_by_namespace": summary_by_namespace,
        "summary_by_severity": summary_by_severity,
        "object_risk_summary": object_risk_summary,
        "findings": findings_with_ids,
        "scan_errors": scan_errors,
    }
    return result


def _parse_include_kinds(raw_value: Optional[str]) -> Optional[Set[str]]:
    if not raw_value:
        return None
    parsed = {token.strip().lower() for token in raw_value.split(",") if token.strip()}
    return parsed or None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan Kubernetes ConfigMaps and Secrets for secret leakage indicators."
    )
    parser.add_argument(
        "-o",
        "--output",
        default="kube_configmap_secret_leakage_report.json",
        help="Output file path (JSON). Default: kube_configmap_secret_leakage_report.json",
    )
    parser.add_argument(
        "-x",
        "--exclude-namespace",
        action="append",
        default=[],
        help="Namespace to exclude from scanning. Can be specified multiple times.",
    )
    parser.add_argument(
        "--include-kinds",
        default=None,
        help="Comma-separated resource kinds to scan. Supported: configmap,secret",
    )
    args = parser.parse_args()

    include_kinds = _parse_include_kinds(args.include_kinds)
    print(f"Starting ConfigMap & Secret leakage scan (cluster: {CLUSTER_NAME})...")
    data = scan_configmaps_and_secrets(
        exclude_namespaces=args.exclude_namespace or None,
        include_kinds=include_kinds,
    )

    print(f"Writing report to {args.output}...")
    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(data, output_file, indent=2, default=str)

    total = data.get("total_findings", 0)
    by_sev = data.get("summary_by_severity", {})
    print(
        f"Done. {total} findings "
        f"(high={by_sev.get('high', 0)}, medium={by_sev.get('medium', 0)}, low={by_sev.get('low', 0)}). "
        f"Report saved to {args.output}"
    )


if __name__ == "__main__":
    main()
