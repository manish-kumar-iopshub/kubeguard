"""Deployment Risk Scoring Engine — scores each Deployment from 0 to 100."""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from kubernetes import client, config

HERE = os.path.dirname(__file__)
SRC = os.path.abspath(os.path.join(HERE, "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

IST = timezone(timedelta(hours=5, minutes=30))
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "null-cluster-name")

DEFAULT_EXCLUDED_NAMESPACES = [
    ns.strip()
    for ns in os.getenv(
        "RISK_SCORER_EXCLUDE_NAMESPACES",
        "kube-system,kube-public,kube-node-lease",
    ).split(",")
    if ns.strip()
]

SUSPICIOUS_ENV_KEYWORDS = {
    kw.strip().lower()
    for kw in os.getenv(
        "RISK_SCORER_SUSPICIOUS_KEYWORDS",
        "password,passwd,pwd,secret,token,api_key,apikey,access_key,private_key,client_secret",
    ).split(",")
    if kw.strip()
}


def get_time_now() -> str:
    return datetime.now(IST).isoformat()


def load_kube_config() -> None:
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


def _is_suspicious_env_name(name: str) -> bool:
    normalized = _normalize_key(name)
    return any(kw in normalized for kw in SUSPICIOUS_ENV_KEYWORDS)


def _get_image_tag(image: str) -> str:
    if "@" in image:
        return "digest"
    if ":" in image:
        return image.rsplit(":", 1)[-1]
    return "latest"


# ---------------------------------------------------------------------------
# PDB helpers
# ---------------------------------------------------------------------------

def _pdb_matches_labels(pdb: Any, pod_labels: Dict[str, str]) -> bool:
    selector = getattr(getattr(pdb, "spec", None), "selector", None)
    if not selector:
        return False
    match_labels = getattr(selector, "match_labels", None) or {}
    if not match_labels:
        return False
    return all(pod_labels.get(k) == v for k, v in match_labels.items())


# ---------------------------------------------------------------------------
# Trivy helper
# ---------------------------------------------------------------------------

def _run_trivy_scan(image: str) -> bool:
    """Return True if image has HIGH/CRITICAL vulnerabilities."""
    try:
        result = subprocess.run(
            [
                "trivy", "image",
                "--severity", "HIGH,CRITICAL",
                "--format", "json",
                "--quiet",
                image,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
        return any(r.get("Vulnerabilities") for r in data.get("Results", []))
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return False


# ---------------------------------------------------------------------------
# Rule checks — each returns a list of deduction dicts
# ---------------------------------------------------------------------------

def _check_reliability(
    dep: Any,
    pod_spec: Any,
    containers: List[Any],
    pdbs: List[Any],
    pod_labels: Dict[str, str],
) -> List[Dict[str, Any]]:
    deductions: List[Dict[str, Any]] = []

    # No readiness probe (-10)
    missing = [c.name for c in containers if not getattr(c, "readiness_probe", None)]
    if missing:
        deductions.append({
            "rule": "no_readiness_probe",
            "category": "reliability",
            "weight": -10,
            "detail": f"Container(s) without readiness probe: {', '.join(missing)}",
        })

    # No liveness probe (-10)
    missing = [c.name for c in containers if not getattr(c, "liveness_probe", None)]
    if missing:
        deductions.append({
            "rule": "no_liveness_probe",
            "category": "reliability",
            "weight": -10,
            "detail": f"Container(s) without liveness probe: {', '.join(missing)}",
        })

    # No resource requests (-15)
    no_req = [
        c.name for c in containers
        if not getattr(c, "resources", None) or not getattr(c.resources, "requests", None)
    ]
    if no_req:
        deductions.append({
            "rule": "no_resource_requests",
            "category": "reliability",
            "weight": -15,
            "detail": f"Container(s) without resource requests: {', '.join(no_req)}",
        })

    # No resource limits (-15)
    no_lim = [
        c.name for c in containers
        if not getattr(c, "resources", None) or not getattr(c.resources, "limits", None)
    ]
    if no_lim:
        deductions.append({
            "rule": "no_resource_limits",
            "category": "reliability",
            "weight": -15,
            "detail": f"Container(s) without resource limits: {', '.join(no_lim)}",
        })

    # Image tag = latest (-10)
    latest = [c.name for c in containers if _get_image_tag(c.image or "") == "latest"]
    if latest:
        deductions.append({
            "rule": "image_tag_latest",
            "category": "reliability",
            "weight": -10,
            "detail": f"Container(s) using 'latest' or untagged image: {', '.join(latest)}",
        })

    # Replicas = 1 (-10)
    replicas = getattr(dep.spec, "replicas", None)
    if replicas is not None and replicas <= 1:
        deductions.append({
            "rule": "single_replica",
            "category": "reliability",
            "weight": -10,
            "detail": f"Only {replicas} replica(s) configured",
        })

    # No PDB (-10)
    if not any(_pdb_matches_labels(pdb, pod_labels) for pdb in pdbs):
        deductions.append({
            "rule": "no_pdb",
            "category": "reliability",
            "weight": -10,
            "detail": "No PodDisruptionBudget matches pod labels",
        })

    return deductions


def _check_security(
    containers: List[Any],
    pod_spec: Any,
) -> List[Dict[str, Any]]:
    deductions: List[Dict[str, Any]] = []

    # Privileged container (-20)
    for c in containers:
        sc = getattr(c, "security_context", None)
        if sc and getattr(sc, "privileged", None):
            deductions.append({
                "rule": "privileged_container",
                "category": "security",
                "weight": -20,
                "detail": f"Container '{c.name}' runs in privileged mode",
            })
            break

    # runAsRoot (-15)
    pod_sc = getattr(pod_spec, "security_context", None)
    explicitly_non_root = False

    if pod_sc:
        if getattr(pod_sc, "run_as_non_root", None):
            explicitly_non_root = True
        run_as_user = getattr(pod_sc, "run_as_user", None)
        if run_as_user is not None and run_as_user > 0:
            explicitly_non_root = True

    for c in containers:
        csc = getattr(c, "security_context", None)
        if not csc:
            continue
        if getattr(csc, "run_as_user", None) == 0:
            explicitly_non_root = False
            break
        if getattr(csc, "run_as_non_root", None):
            explicitly_non_root = True
        cru = getattr(csc, "run_as_user", None)
        if cru is not None and cru > 0:
            explicitly_non_root = True

    if not explicitly_non_root:
        deductions.append({
            "rule": "run_as_root",
            "category": "security",
            "weight": -15,
            "detail": "Pod may run as root (no runAsNonRoot: true or runAsUser > 0)",
        })

    # No securityContext (-10)
    has_any_sc = pod_sc is not None
    if not has_any_sc:
        has_any_sc = any(getattr(c, "security_context", None) for c in containers)
    if not has_any_sc:
        deductions.append({
            "rule": "no_security_context",
            "category": "security",
            "weight": -10,
            "detail": "No securityContext at pod or container level",
        })

    # Secrets in env vars (-10)
    for c in containers:
        for env in (getattr(c, "env", None) or []):
            env_name = getattr(env, "name", "") or ""
            env_value = getattr(env, "value", None)
            if env_value and _is_suspicious_env_name(env_name):
                deductions.append({
                    "rule": "secrets_in_env_vars",
                    "category": "security",
                    "weight": -10,
                    "detail": f"Plaintext secret-like env var '{env_name}' in container '{c.name}'",
                })
                return deductions
    return deductions


def _check_scaling(
    pod_spec: Any,
    hpa_targets: Set[Tuple[str, str]],
    namespace: str,
    name: str,
) -> List[Dict[str, Any]]:
    deductions: List[Dict[str, Any]] = []

    # No HPA (-10)
    if (namespace, name) not in hpa_targets:
        deductions.append({
            "rule": "no_hpa",
            "category": "scaling",
            "weight": -10,
            "detail": "No HorizontalPodAutoscaler targets this deployment",
        })

    # No anti-affinity (-10)
    affinity = getattr(pod_spec, "affinity", None)
    paa = getattr(affinity, "pod_anti_affinity", None) if affinity else None
    has_anti_affinity = False
    if paa:
        preferred = getattr(paa, "preferred_during_scheduling_ignored_during_execution", None) or []
        required = getattr(paa, "required_during_scheduling_ignored_during_execution", None) or []
        has_anti_affinity = bool(preferred or required)
    if not has_anti_affinity:
        deductions.append({
            "rule": "no_anti_affinity",
            "category": "scaling",
            "weight": -10,
            "detail": "No pod anti-affinity rules defined",
        })

    # No topology spread (-10)
    tsc = getattr(pod_spec, "topology_spread_constraints", None) or []
    if not tsc:
        deductions.append({
            "rule": "no_topology_spread",
            "category": "scaling",
            "weight": -10,
            "detail": "No topologySpreadConstraints defined",
        })

    return deductions


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def _should_skip_workload(namespace: str, name: str, skip_set: Set[str]) -> bool:
    """Check if a workload should be skipped by name or namespace/name."""
    return name in skip_set or f"{namespace}/{name}" in skip_set


def score_deployments(
    *,
    exclude_namespaces: Optional[List[str]] = None,
    skip_workloads: Optional[List[str]] = None,
    enable_trivy: bool = False,
) -> Dict[str, Any]:
    load_kube_config()
    apps_v1 = client.AppsV1Api()
    policy_v1 = client.PolicyV1Api()
    autoscaling_v1 = client.AutoscalingV1Api()

    exclude_set = set(DEFAULT_EXCLUDED_NAMESPACES)
    exclude_set.update(ns.strip() for ns in (exclude_namespaces or []) if ns and ns.strip())
    skip_set = {w.strip() for w in (skip_workloads or []) if w.strip()}

    print(f"Excluding namespaces: {', '.join(sorted(exclude_set))}")
    if skip_set:
        print(f"Skipping workloads: {', '.join(sorted(skip_set))}")

    # 1. Fetch Deployments
    print("[1/4] Fetching Deployments...")
    all_deps = apps_v1.list_deployment_for_all_namespaces().items
    deployments = [
        d for d in all_deps
        if d.metadata.namespace not in exclude_set
        and not _should_skip_workload(d.metadata.namespace, d.metadata.name, skip_set)
    ]
    skipped = len(all_deps) - len(deployments)
    print(f"       {len(deployments)} deployments to score (excluded {skipped})")

    # 2. Fetch PDBs grouped by namespace
    print("[2/4] Fetching PodDisruptionBudgets...")
    pdbs_by_ns: Dict[str, List[Any]] = {}
    try:
        for pdb in policy_v1.list_pod_disruption_budget_for_all_namespaces().items:
            pdbs_by_ns.setdefault(pdb.metadata.namespace, []).append(pdb)
        print(f"       Retrieved {sum(len(v) for v in pdbs_by_ns.values())} PDBs")
    except Exception as exc:
        print(f"       Failed to fetch PDBs: {exc}")

    # 3. Fetch HPAs and build lookup set
    print("[3/4] Fetching HorizontalPodAutoscalers...")
    hpa_targets: Set[Tuple[str, str]] = set()
    try:
        for hpa in autoscaling_v1.list_horizontal_pod_autoscaler_for_all_namespaces().items:
            ref = getattr(hpa.spec, "scale_target_ref", None)
            if ref and getattr(ref, "kind", "") == "Deployment":
                hpa_targets.add((hpa.metadata.namespace, ref.name))
        print(f"       {len(hpa_targets)} HPAs targeting deployments")
    except Exception as exc:
        print(f"       Failed to fetch HPAs: {exc}")

    # 4. Optional Trivy scan
    trivy_vulnerable: Set[str] = set()
    if enable_trivy:
        unique_images: Set[str] = set()
        for dep in deployments:
            tpl_spec = getattr(getattr(dep.spec, "template", None), "spec", None)
            if not tpl_spec:
                continue
            for c in (getattr(tpl_spec, "containers", None) or []):
                if c.image:
                    unique_images.add(c.image)
        print(f"[4/4] Scanning {len(unique_images)} unique images with Trivy...")
        for idx, img in enumerate(sorted(unique_images), 1):
            print(f"       [{idx}/{len(unique_images)}] {img}")
            if _run_trivy_scan(img):
                trivy_vulnerable.add(img)
        print(f"       {len(trivy_vulnerable)} images with HIGH/CRITICAL vulnerabilities")
    else:
        print("[4/4] Trivy scan skipped (use --enable-trivy to enable)")

    # Score each deployment
    print("Scoring deployments...")
    scored: List[Dict[str, Any]] = []
    scan_errors: List[Dict[str, str]] = []

    for dep in deployments:
        ns = dep.metadata.namespace
        name = dep.metadata.name
        template = getattr(dep.spec, "template", None)
        tpl_spec = getattr(template, "spec", None) if template else None
        if not tpl_spec:
            scan_errors.append({"deployment": f"{ns}/{name}", "error": "missing pod template spec"})
            continue

        containers = getattr(tpl_spec, "containers", None) or []
        pod_labels = getattr(template.metadata, "labels", None) or {} if template.metadata else {}

        deductions: List[Dict[str, Any]] = []

        deductions.extend(_check_reliability(dep, tpl_spec, containers, pdbs_by_ns.get(ns, []), pod_labels))

        if enable_trivy:
            for c in containers:
                if c.image in trivy_vulnerable:
                    deductions.append({
                        "rule": "trivy_vulnerabilities",
                        "category": "reliability",
                        "weight": -10,
                        "detail": f"Image '{c.image}' has HIGH/CRITICAL vulnerabilities",
                    })
                    break

        deductions.extend(_check_security(containers, tpl_spec))
        deductions.extend(_check_scaling(tpl_spec, hpa_targets, ns, name))

        score = max(0, 100 + sum(d["weight"] for d in deductions))

        if score >= 80:
            risk_level = "Low"
        elif score >= 60:
            risk_level = "Medium"
        elif score >= 40:
            risk_level = "High"
        else:
            risk_level = "Critical"

        scored.append({
            "namespace": ns,
            "deployment": name,
            "score": score,
            "risk_level": risk_level,
            "replicas": getattr(dep.spec, "replicas", None),
            "deductions": deductions,
        })

    scored.sort(key=lambda x: (x["score"], x["namespace"], x["deployment"]))

    risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for s in scored:
        risk_dist[s["risk_level"]] += 1
    avg_score = round(sum(s["score"] for s in scored) / len(scored), 1) if scored else 0

    return {
        "timestamp": get_time_now(),
        "cluster_name": CLUSTER_NAME,
        "exclude_namespaces": sorted(exclude_set),
        "skip_workloads": sorted(skip_set),
        "trivy_enabled": enable_trivy,
        "total_deployments_scored": len(scored),
        "average_score": avg_score,
        "risk_distribution": risk_dist,
        "deployments": scored,
        "scan_errors": scan_errors,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Score Kubernetes Deployments from 0-100 on reliability, security, and scaling."
    )
    parser.add_argument(
        "-o", "--output",
        default="deployment_risk_scores.json",
        help="Output file path. Default: deployment_risk_scores.json",
    )
    parser.add_argument(
        "-x", "--exclude-namespace",
        action="append",
        default=[],
        help="Namespace to exclude. Can be specified multiple times.",
    )
    parser.add_argument(
        "-s", "--skip-workload",
        action="append",
        default=[],
        help=(
            "Workload to skip. Use 'name' or 'namespace/name'. "
            "Can be specified multiple times, e.g. -s my-deploy -s prod/nginx"
        ),
    )
    parser.add_argument(
        "--enable-trivy",
        action="store_true",
        default=False,
        help="Enable Trivy image vulnerability scanning (requires trivy CLI).",
    )
    args = parser.parse_args()

    print(f"Starting Deployment Risk Scoring (cluster: {CLUSTER_NAME})...")
    data = score_deployments(
        exclude_namespaces=args.exclude_namespace or None,
        skip_workloads=args.skip_workload or None,
        enable_trivy=args.enable_trivy,
    )

    print(f"Writing report to {args.output}...")
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2, default=str)

    avg = data["average_score"]
    dist = data["risk_distribution"]
    print(
        f"Done. {data['total_deployments_scored']} deployments scored (avg: {avg}). "
        f"Critical={dist['Critical']}, High={dist['High']}, "
        f"Medium={dist['Medium']}, Low={dist['Low']}. "
        f"Report saved to {args.output}"
    )


if __name__ == "__main__":
    main()
