"""Scan Kubernetes runtime resources for potential secret leakage."""

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

# Resource kinds included in scan when user does not pass --include-kinds.
DEFAULT_INCLUDE_KINDS = {
    kind.strip().lower()
    for kind in os.getenv(
        "SECRET_SCANNER_INCLUDE_KINDS",
        "pod,deployment,statefulset,daemonset,configmap,secret",
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

# Severity ranking for sorting object summaries.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
# Supported values accepted in --include-kinds.
SUPPORTED_KINDS = {"pod", "deployment", "statefulset", "daemonset", "configmap", "secret"}

# High-confidence value signatures used in conservative mode.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b")
PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.IGNORECASE,
)


# Return current timestamp in ISO format.
def get_time_now() -> str:
    return datetime.now(IST).isoformat()


# Load Kubernetes config from in-cluster first, then local kubeconfig.
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


# Normalize key names so matching works across different naming styles.
def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


# Decide whether a key name is suspicious and not explicitly allowlisted.
def _is_suspicious_key(key: Optional[str]) -> bool:
    if not key:
        return False
    normalized = _normalize_key(key)
    if normalized in ALLOWLIST_KEYS:
        return False
    return any(keyword in normalized for keyword in SUSPICIOUS_KEYWORDS)


# Detect strong secret signatures from raw string values.
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


# Mask evidence so reports never expose full secrets.
def _mask_value(value: Optional[str]) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}...{s[-4:]}"


# Build one normalized finding object for report output.
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


# Scan labels/annotations for suspicious keys and secret-like values.
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


# Scan env/envFrom for hardcoded or weakly-stored secret-like data.
def _scan_container_env(
    *,
    namespace: str,
    kind: str,
    object_name: str,
    container: Any,
    container_type: str = "containers",
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cname = getattr(container, "name", None)
    env_list = getattr(container, "env", None) or []
    env_from_list = getattr(container, "env_from", None) or []

    for env in env_list:
        env_name = getattr(env, "name", None) or ""
        env_value = getattr(env, "value", None)
        env_value_from = getattr(env, "value_from", None)
        field_path = f"spec.{container_type}[{cname}].env[{env_name}]"

        if _is_suspicious_key(env_name):
            if env_value:
                findings.append(
                    _create_finding(
                        severity="high",
                        rule_id="hardcoded-secret-like-env-name",
                        message="Environment variable with sensitive key name is set using plaintext value.",
                        namespace=namespace,
                        kind=kind,
                        object_name=object_name,
                        container=cname,
                        field_path=field_path,
                        evidence=env_value,
                    )
                )
            elif env_value_from and getattr(env_value_from, "config_map_key_ref", None):
                cm_ref = env_value_from.config_map_key_ref
                findings.append(
                    _create_finding(
                        severity="medium",
                        rule_id="sensitive-env-from-configmap",
                        message="Sensitive env var appears to be sourced from ConfigMap, which is plaintext by design.",
                        namespace=namespace,
                        kind=kind,
                        object_name=object_name,
                        container=cname,
                        field_path=f"{field_path}.valueFrom.configMapKeyRef",
                        evidence=f"{getattr(cm_ref, 'name', '')}:{getattr(cm_ref, 'key', '')}",
                        recommendation="Store secret-like values in Secret and use valueFrom.secretKeyRef.",
                    )
                )

        if env_value:
            signature = _match_strong_secret_signature(env_value)
            if signature:
                findings.append(
                    _create_finding(
                        severity="high",
                        rule_id="env-contains-secret-signature",
                        message=f"Plaintext env value matches strong secret signature ({signature}).",
                        namespace=namespace,
                        kind=kind,
                        object_name=object_name,
                        container=cname,
                        field_path=f"{field_path}.value",
                        evidence=env_value,
                    )
                )

    for idx, env_from in enumerate(env_from_list):
        cm_ref = getattr(env_from, "config_map_ref", None)
        if cm_ref and getattr(cm_ref, "name", None) and _is_suspicious_key(cm_ref.name):
            findings.append(
                _create_finding(
                    severity="medium",
                    rule_id="envfrom-suspicious-configmap-name",
                    message="envFrom references a ConfigMap with suspicious secret-like name.",
                    namespace=namespace,
                    kind=kind,
                    object_name=object_name,
                    container=cname,
                    field_path=f"spec.{container_type}[{cname}].envFrom[{idx}].configMapRef.name",
                    evidence=cm_ref.name,
                    recommendation="Verify sensitive values are not stored in ConfigMap.",
                )
            )

    return findings


# Get pod spec from either Pod object or workload template spec.
def _extract_pod_spec_from_workload(obj: Any, kind: str) -> Optional[Any]:
    if kind == "Pod":
        return getattr(obj, "spec", None)
    spec = getattr(obj, "spec", None)
    template = getattr(spec, "template", None) if spec else None
    return getattr(template, "spec", None) if template else None


# Scan one workload object (metadata + containers + initContainers).
def _scan_workload_object(obj: Any, kind: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    metadata = getattr(obj, "metadata", None)
    if not metadata or not metadata.name or not metadata.namespace:
        return findings

    namespace = metadata.namespace
    object_name = metadata.name
    pod_spec = _extract_pod_spec_from_workload(obj, kind)

    findings.extend(
        _scan_annotations_and_labels(
            metadata=metadata,
            namespace=namespace,
            kind=kind,
            object_name=object_name,
        )
    )

    if not pod_spec:
        return findings

    containers = getattr(pod_spec, "containers", None) or []
    init_containers = getattr(pod_spec, "init_containers", None) or []

    for container in containers:
        findings.extend(
            _scan_container_env(
                namespace=namespace,
                kind=kind,
                object_name=object_name,
                container=container,
                container_type="containers",
            )
        )

    for container in init_containers:
        findings.extend(
            _scan_container_env(
                namespace=namespace,
                kind=kind,
                object_name=object_name,
                container=container,
                container_type="initContainers",
            )
        )

    return findings


# Scan ConfigMap content and metadata for likely secret leakage.
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


# Scan Secret metadata and stringData misuse patterns (no data decode).
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


# Add stable IDs so each finding can be tracked uniquely.
def _append_findings_with_ids(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    indexed: List[Dict[str, Any]] = []
    for idx, finding in enumerate(findings, start=1):
        with_id = dict(finding)
        with_id["id"] = f"F-{idx:05d}"
        indexed.append(with_id)
    return indexed


# Build per-namespace, per-severity, and per-object risk summaries.
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


# Main orchestrator: scan selected kinds and return complete JSON-ready report.
def scan_kubernetes_for_secret_leaks(
    *,
    exclude_namespaces: Optional[List[str]] = None,
    include_kinds: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Scan Kubernetes runtime resources for likely secret leakage patterns."""
    load_kube_config()
    core_v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()

    include = {k.lower() for k in (include_kinds or DEFAULT_INCLUDE_KINDS)}
    exclude_set = set(DEFAULT_EXCLUDED_NAMESPACES)
    exclude_set.update(ns.strip() for ns in (exclude_namespaces or []) if ns and ns.strip())

    findings: List[Dict[str, Any]] = []
    scan_errors: List[Dict[str, str]] = []
    object_scan_counts: Dict[str, int] = {
        "pod": 0,
        "deployment": 0,
        "statefulset": 0,
        "daemonset": 0,
        "configmap": 0,
        "secret": 0,
    }

    unknown_kinds = sorted(include - SUPPORTED_KINDS)
    if unknown_kinds:
        print(f"Ignoring unsupported include kinds: {', '.join(unknown_kinds)}")

    print(f"Scanning kinds: {', '.join(sorted(include & SUPPORTED_KINDS))}")
    print(f"Excluding namespaces: {', '.join(sorted(exclude_set))}")

    # Scan Pods.
    if "pod" in include:
        try:
            print("[1/6] Fetching Pods from all namespaces...")
            pods = core_v1.list_pod_for_all_namespaces().items
            print(f"       Retrieved {len(pods)} pods, scanning...")
            for pod in pods:
                ns = pod.metadata.namespace
                if ns in exclude_set:
                    continue
                object_scan_counts["pod"] += 1
                findings.extend(_scan_workload_object(pod, "Pod"))
            print(f"       Scanned {object_scan_counts['pod']} pods ({len(findings)} findings so far)")
        except Exception as exc:
            scan_errors.append({"kind": "pod", "error": str(exc)})
            print(f"       FAILED to scan Pods: {exc}")

    # Scan Deployments.
    if "deployment" in include:
        try:
            print("[2/6] Fetching Deployments from all namespaces...")
            deployments = apps_v1.list_deployment_for_all_namespaces().items
            print(f"       Retrieved {len(deployments)} deployments, scanning...")
            for dep in deployments:
                ns = dep.metadata.namespace
                if ns in exclude_set:
                    continue
                object_scan_counts["deployment"] += 1
                findings.extend(_scan_workload_object(dep, "Deployment"))
            print(f"       Scanned {object_scan_counts['deployment']} deployments ({len(findings)} findings so far)")
        except Exception as exc:
            scan_errors.append({"kind": "deployment", "error": str(exc)})
            print(f"       FAILED to scan Deployments: {exc}")

    # Scan StatefulSets.
    if "statefulset" in include:
        try:
            print("[3/6] Fetching StatefulSets from all namespaces...")
            statefulsets = apps_v1.list_stateful_set_for_all_namespaces().items
            print(f"       Retrieved {len(statefulsets)} statefulsets, scanning...")
            for sts in statefulsets:
                ns = sts.metadata.namespace
                if ns in exclude_set:
                    continue
                object_scan_counts["statefulset"] += 1
                findings.extend(_scan_workload_object(sts, "StatefulSet"))
            print(f"       Scanned {object_scan_counts['statefulset']} statefulsets ({len(findings)} findings so far)")
        except Exception as exc:
            scan_errors.append({"kind": "statefulset", "error": str(exc)})
            print(f"       FAILED to scan StatefulSets: {exc}")

    # Scan DaemonSets.
    if "daemonset" in include:
        try:
            print("[4/6] Fetching DaemonSets from all namespaces...")
            daemonsets = apps_v1.list_daemon_set_for_all_namespaces().items
            print(f"       Retrieved {len(daemonsets)} daemonsets, scanning...")
            for ds in daemonsets:
                ns = ds.metadata.namespace
                if ns in exclude_set:
                    continue
                object_scan_counts["daemonset"] += 1
                findings.extend(_scan_workload_object(ds, "DaemonSet"))
            print(f"       Scanned {object_scan_counts['daemonset']} daemonsets ({len(findings)} findings so far)")
        except Exception as exc:
            scan_errors.append({"kind": "daemonset", "error": str(exc)})
            print(f"       FAILED to scan DaemonSets: {exc}")

    # Scan ConfigMaps.
    if "configmap" in include:
        try:
            print("[5/6] Fetching ConfigMaps from all namespaces...")
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

    # Scan Secrets (metadata-oriented checks in this version).
    if "secret" in include:
        try:
            print("[6/6] Fetching Secrets from all namespaces...")
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
        "scanner_mode": "conservative_runtime_only",
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


# Parse comma-separated include-kinds CLI value into a normalized set.
def _parse_include_kinds(raw_value: Optional[str]) -> Optional[Set[str]]:
    if not raw_value:
        return None
    parsed = {token.strip().lower() for token in raw_value.split(",") if token.strip()}
    return parsed or None


# CLI entrypoint: parse args, run scanner, and write JSON report.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan Kubernetes runtime resources for secret leakage indicators (conservative mode)."
    )
    parser.add_argument(
        "-o",
        "--output",
        default="kube_secret_leakage_report.json",
        help="Output file path (JSON). Default: kube_secret_leakage_report.json",
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
        help=(
            "Comma-separated resource kinds to scan. "
            "Supported: pod,deployment,statefulset,daemonset,configmap,secret"
        ),
    )
    args = parser.parse_args()

    include_kinds = _parse_include_kinds(args.include_kinds)
    print(f"Starting Kubernetes secret leakage scan (cluster: {CLUSTER_NAME})...")
    data = scan_kubernetes_for_secret_leaks(
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


# Execute CLI flow when script is run directly.
if __name__ == "__main__":
    main()
