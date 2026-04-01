"""Scan Kubernetes cluster for unhealthy pods and collect diagnostics."""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from kubernetes import client, config

HERE = os.path.dirname(__file__)
SRC = os.path.abspath(os.path.join(HERE, "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

IST = timezone(timedelta(hours=5, minutes=30))
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "iopshub-eks-prod")

DEFAULT_EXCLUDED_NAMESPACES = [
    ns.strip()
    for ns in os.getenv(
        "UNHEALTHY_POD_EXCLUDE_NAMESPACES",
        "kube-system,kube-public,kube-node-lease,prowler",
    ).split(",")
    if ns.strip()
]

UNHEALTHY_WAITING_REASONS = {
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "CreateContainerError",
}

UNHEALTHY_TERMINATED_REASONS = {
    "OOMKilled",
}

UNHEALTHY_POD_PHASES = {
    "Failed",
    "Unknown",
}


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
        except Exception as e:
            print(f"Failed to load Kubernetes configuration: {e}")
            raise


def detect_unhealthy_state(pod: client.V1Pod) -> Optional[Dict[str, Any]]:
    """Return detection info if pod is unhealthy, else None."""
    phase = getattr(pod.status, "phase", None)
    container_statuses = getattr(pod.status, "container_statuses", None) or []
    init_container_statuses = getattr(pod.status, "init_container_statuses", None) or []

    def _check_statuses(statuses: List[client.V1ContainerStatus]) -> Optional[Dict[str, Any]]:
        for cs in statuses:
            cname = getattr(cs, "name", None)
            state = getattr(cs, "state", None)
            if not state:
                continue

            waiting = getattr(state, "waiting", None)
            if waiting and waiting.reason:
                if waiting.reason in UNHEALTHY_WAITING_REASONS or waiting.reason not in {
                    "ContainerCreating",
                    "PodInitializing",
                }:
                    return {
                        "reason": waiting.reason,
                        "container": cname,
                        "state": "Waiting",
                        "message": getattr(waiting, "message", None),
                    }

            terminated = getattr(state, "terminated", None)
            if terminated:
                exit_code = getattr(terminated, "exit_code", None)
                reason = getattr(terminated, "reason", None)
                if (
                    reason in UNHEALTHY_TERMINATED_REASONS
                    or (exit_code is not None and exit_code != 0)
                ):
                    return {
                        "reason": reason or "TerminatedNonZeroExit",
                        "container": cname,
                        "state": "Terminated",
                        "exit_code": exit_code,
                        "message": getattr(terminated, "message", None),
                    }
        return None

    detected = _check_statuses(container_statuses)
    if detected:
        return detected

    detected = _check_statuses(init_container_statuses)
    if detected:
        return detected

    if phase in UNHEALTHY_POD_PHASES:
        return {
            "reason": f"PodPhase{phase}",
            "container": None,
            "state": "PodPhase",
        }

    return None


def _get_events_for_pod(v1: client.CoreV1Api, namespace: str, pod_name: str) -> List[str]:
    """Return deduplicated Warning event messages for a pod."""
    messages: List[str] = []
    seen: set = set()
    try:
        ev_list = v1.list_namespaced_event(
            namespace=namespace,
            field_selector=f"involvedObject.kind=Pod,involvedObject.name={pod_name}",
        )
        for ev in ev_list.items:
            if getattr(ev, "type", None) != "Warning":
                continue
            msg = getattr(ev, "message", None) or ""
            if msg and msg not in seen:
                seen.add(msg)
                messages.append(msg)
    except Exception as e:
        print(f"Failed to list events for {namespace}/{pod_name}: {e}")
    return messages


def _get_node_info(v1: client.CoreV1Api, node_name: Optional[str]) -> Optional[Dict[str, Any]]:
    if not node_name:
        return None
    try:
        node = v1.read_node(node_name)
        labels = node.metadata.labels or {}
        return {
            "name": node.metadata.name,
            "instance_type": labels.get("node.kubernetes.io/instance-type", "unknown"),
            "zone": labels.get("topology.kubernetes.io/zone", "unknown"),
        }
    except Exception as e:
        print(f"Failed to read node {node_name}: {e}")
        return None


LOG_TAIL_LINES = 50
LOG_MAX_CHARS = 4000


def _clean_log_error(raw: str) -> str:
    """Extract short error reason from K8s API error responses."""
    if '"message"' in raw:
        import re
        m = re.search(r'"message"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
        if m:
            return m.group(1).replace('\\"', '"').replace("\\n", " ").replace("\\", "")
    return raw.split("\n")[0][:200]


def _get_logs_for_pod(
    v1: client.CoreV1Api,
    namespace: str,
    pod_name: str,
    container_name: Optional[str],
) -> Dict[str, str]:
    last_logs = ""
    previous_logs = ""
    target_container = container_name

    if not target_container:
        try:
            pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            containers = pod.spec.containers or []
            if containers:
                target_container = containers[0].name
        except Exception:
            pass

    if not target_container:
        return {"last_logs": "", "previous_logs": ""}

    try:
        last_logs = v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=target_container,
            tail_lines=LOG_TAIL_LINES,
        )
    except Exception as e:
        last_logs = _clean_log_error(str(e))

    try:
        previous_logs = v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=target_container,
            previous=True,
            tail_lines=LOG_TAIL_LINES,
        )
    except Exception as e:
        previous_logs = _clean_log_error(str(e))

    if len(last_logs) > LOG_MAX_CHARS:
        last_logs = last_logs[-LOG_MAX_CHARS:]
    if len(previous_logs) > LOG_MAX_CHARS:
        previous_logs = previous_logs[-LOG_MAX_CHARS:]

    return {"last_logs": last_logs, "previous_logs": previous_logs}


def _build_diagnostic_context(
    v1: client.CoreV1Api,
    pod: client.V1Pod,
    detection: Dict[str, Any],
) -> Dict[str, Any]:
    namespace = pod.metadata.namespace
    pod_name = pod.metadata.name
    node_name = getattr(pod.spec, "node_name", None)

    owner = None
    if pod.metadata.owner_references:
        o = pod.metadata.owner_references[0]
        owner = f"{o.kind}/{o.name}"

    images = [c.image for c in (pod.spec.containers or [])]

    node_info = _get_node_info(v1, node_name)
    warning_events = _get_events_for_pod(v1, namespace, pod_name)
    logs = _get_logs_for_pod(v1, namespace, pod_name, detection.get("container"))

    result: Dict[str, Any] = {
        "owner": owner,
        "images": images,
    }
    if node_info:
        result["node"] = node_info
    if warning_events:
        result["warning_events"] = warning_events
    if logs.get("last_logs"):
        result["last_logs"] = logs["last_logs"]
    if logs.get("previous_logs"):
        result["previous_logs"] = logs["previous_logs"]
    return result


def collect_unhealthy_pods(
    exclude_namespaces: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Scan cluster for unhealthy pods and collect diagnostics."""
    load_kube_config()
    v1 = client.CoreV1Api()

    print("Fetching pods from all namespaces...")
    pods = v1.list_pod_for_all_namespaces().items
    print(f"Retrieved {len(pods)} pods")
    summaries: List[Dict[str, Any]] = []

    exclude_set = set(DEFAULT_EXCLUDED_NAMESPACES)
    exclude_set.update(
        ns.strip() for ns in (exclude_namespaces or []) if ns and ns.strip()
    )
    print(f"Excluding namespaces: {', '.join(sorted(exclude_set))}")

    for pod in pods:
        ns = pod.metadata.namespace
        if ns in exclude_set:
            continue

        detection = detect_unhealthy_state(pod)
        if not detection:
            continue

        print(f"Detected unhealthy pod {ns}/{pod.metadata.name}: {detection}")

        diagnostics = _build_diagnostic_context(v1, pod, detection)

        restart_count = 0
        container_statuses = getattr(pod.status, "container_statuses", None) or []
        for cs in container_statuses:
            try:
                restart_count = max(restart_count, int(getattr(cs, "restart_count", 0)))
            except Exception:
                continue

        summaries.append(
            {
                "pod_name": pod.metadata.name,
                "namespace": ns,
                "reason": detection.get("reason"),
                "state": detection.get("state"),
                "exit_code": detection.get("exit_code"),
                "node_name": getattr(pod.spec, "node_name", None),
                "restart_count": restart_count,
                "diagnostics": diagnostics,
            }
        )

    print(f"Scan complete. Found {len(summaries)} unhealthy pods out of {len(pods)} total")

    return {
        "timestamp": get_time_now(),
        "cluster_name": CLUSTER_NAME,
        "total_pods_scanned": len(pods),
        "unhealthy_pod_count": len(summaries),
        "unhealthy_pods": summaries,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Scan Kubernetes cluster for unhealthy pods and collect diagnostics.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="unhealthy_pods_report.json",
        help="Output file path (JSON). Default: unhealthy_pods_report.json",
    )
    parser.add_argument(
        "-x",
        "--exclude-namespace",
        action="append",
        default=[],
        help=(
            "Namespace to exclude from scanning. "
            "Can be specified multiple times, e.g. -x kube-system -x infra"
        ),
    )
    args = parser.parse_args()

    print(f"Starting unhealthy pod scan (cluster: {CLUSTER_NAME})...")
    data = collect_unhealthy_pods(
        exclude_namespaces=args.exclude_namespace or None,
    )

    print(f"Writing report to {args.output}...")
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"Done. {data['unhealthy_pod_count']} unhealthy pods found. Report saved to {args.output}")


if __name__ == "__main__":
    main()
