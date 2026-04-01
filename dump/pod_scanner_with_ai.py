import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from kubernetes import client, config

HERE = os.path.dirname(__file__)
SRC = os.path.abspath(os.path.join(HERE, "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Basic configuration (override via environment variables)
IST = timezone(timedelta(hours=5, minutes=30))
CLUSTER_NAME = os.getenv("CLUSTER_NAME", "iopshub-eks-prod")

# Default namespaces to skip from analysis (can be overridden via CLI/env)
DEFAULT_EXCLUDED_NAMESPACES = [
    ns.strip()
    for ns in os.getenv(
        "UNHEALTHY_POD_EXCLUDE_NAMESPACES",
        "kube-system,kube-public,kube-node-lease,prowler",
    ).split(",")
    if ns.strip()
]

# LLM configuration (override via environment variables)
DEFAULT_LLM_RCA_PROMPT = """
Answer as fast as you can, You are a senior Kubernetes SRE.
Given RAW DATA describing an unhealthy pod (including pod spec, status, events, logs, resource requests/limits, node information, and restart history),
analyze the situation and produce a concise root-cause analysis and remediation plan.
Also use kubectl logs --previous feature to analyze the logs of the pod if restarting multiple times

You MUST return ONLY a single JSON object (no markdown, no code fences, no surrounding text).
The response JSON MUST conform to this schema:

{
  "type": "object",
  "properties": {
    "probable_root_cause": { "type": "string", "description": "Short human-readable summary of the most likely root cause." },
    "confidence": { "type": "number", "description": "Confidence in the root cause, between 0 and 1." },
    "suggested_fix": { "type": "string", "description": "Concrete remediation steps, including any configuration changes." },
    "yaml_patch_example": { "type": "string", "description": "Minimal Kubernetes YAML patch that could be applied to fix the issue (for example patching the parent Deployment / StatefulSet / DaemonSet / Pod spec)." }
  },
  "required": ["probable_root_cause", "confidence", "suggested_fix", "yaml_patch_example"],
  "additionalProperties": false
}

Return exactly one JSON object matching this schema. Do not include any markdown fences or text outside the JSON object."""

LLM_RCA_PROMPT = os.getenv("LLM_RCA_PROMPT", DEFAULT_LLM_RCA_PROMPT)
LLM_MODEL = os.getenv("LLM_MODEL", "phi:latest")
LLM_API_BASE_URL = os.getenv("LLM_API_BASE_URL", "http://localhost:11434")
LLM_CONNECT_TIMEOUT_SECONDS = int(os.getenv("LLM_CONNECT_TIMEOUT_SECONDS", "15"))
LLM_READ_TIMEOUT_SECONDS = int(os.getenv("LLM_READ_TIMEOUT_SECONDS", "600"))

# Unhealthy detection conditions
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
                # Treat all non-transient waiting reasons as unhealthy, plus explicit ones
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

    # Check app containers
    detected = _check_statuses(container_statuses)
    if detected:
        return detected

    # Check init containers as well
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


def _get_events_for_pod(v1: client.CoreV1Api, namespace: str, pod_name: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    try:
        ev_list = v1.list_namespaced_event(
            namespace=namespace,
            field_selector=f"involvedObject.kind=Pod,involvedObject.name={pod_name}",
        )
        for ev in ev_list.items:
            events.append(
                {
                    "reason": getattr(ev, "reason", None),
                    "message": getattr(ev, "message", None),
                    "type": getattr(ev, "type", None),
                    "count": getattr(ev, "count", None),
                    "first_timestamp": ev.first_timestamp.isoformat()
                    if getattr(ev, "first_timestamp", None)
                    else None,
                    "last_timestamp": ev.last_timestamp.isoformat()
                    if getattr(ev, "last_timestamp", None)
                    else None,
                }
            )
    except Exception as e:
        print(f"Failed to list events for {namespace}/{pod_name}: {e}")
    return events


def _get_node_info(v1: client.CoreV1Api, node_name: Optional[str]) -> Optional[Dict[str, Any]]:
    if not node_name:
        return None
    try:
        node = v1.read_node(node_name)
        return {
            "name": node.metadata.name,
            "labels": node.metadata.labels,
            "capacity": getattr(node.status, "capacity", None),
            "allocatable": getattr(node.status, "allocatable", None),
        }
    except Exception as e:
        print(f"Failed to read node {node_name}: {e}")
        return None


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
        except Exception as e:
            print(
                f"Failed to load pod to determine container for logs {namespace}/{pod_name}: {e}"
            )

    if not target_container:
        return {"last_logs": "", "previous_logs": ""}

    try:
        last_logs = v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=target_container,
            tail_lines=200,
        )
    except Exception as e:
        last_logs = f"Failed to fetch logs: {e}"

    try:
        previous_logs = v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=target_container,
            previous=True,
            tail_lines=200,
        )
    except Exception as e:
        previous_logs = f"Failed to fetch previous logs: {e}"

    return {"last_logs": last_logs, "previous_logs": previous_logs}


def _build_ai_context_payload(
    v1: client.CoreV1Api,
    pod: client.V1Pod,
    detection: Dict[str, Any],
) -> Dict[str, Any]:
    namespace = pod.metadata.namespace
    pod_name = pod.metadata.name
    node_name = getattr(pod.spec, "node_name", None)

    owner_references = []
    if pod.metadata.owner_references:
        for o in pod.metadata.owner_references:
            owner_references.append(
                {
                    "kind": o.kind,
                    "name": o.name,
                    "uid": o.uid,
                    "controller": getattr(o, "controller", None),
                }
            )

    resources = []
    for c in pod.spec.containers or []:
        res = c.resources or client.V1ResourceRequirements()
        resources.append(
            {
                "name": c.name,
                "image": c.image,
                "requests": res.requests or {},
                "limits": res.limits or {},
            }
        )

    restart_count = 0
    container_statuses = getattr(pod.status, "container_statuses", None) or []
    for cs in container_statuses:
        try:
            restart_count = max(restart_count, int(getattr(cs, "restart_count", 0)))
        except Exception:
            continue

    node_info = _get_node_info(v1, node_name)
    events = _get_events_for_pod(v1, namespace, pod_name)
    logs = _get_logs_for_pod(
        v1,
        namespace,
        pod_name,
        detection.get("container"),
    )

    context = {
        "pod_name": pod_name,
        "namespace": namespace,
        "reason": detection.get("reason"),
        "state": detection.get("state"),
        "exit_code": detection.get("exit_code"),
        "phase": getattr(pod.status, "phase", None),
        "node_name": node_name,
        "cluster_name": CLUSTER_NAME,
        "restart_count": restart_count,
        "owner_references": owner_references,
        "resources": resources,
        "node": node_info,
        "recent_events": events,
        "last_logs": logs.get("last_logs"),
        "previous_logs": logs.get("previous_logs"),
        "pod_spec": pod.spec.to_dict() if hasattr(pod.spec, "to_dict") else None,
        "pod_status": pod.status.to_dict() if hasattr(pod.status, "to_dict") else None,
    }
    return context


def call_llm_for_context(raw_context: Dict[str, Any]) -> Dict[str, Any]:
    """Call Ollama /api/generate with structured context and return parsed response."""
    result: Dict[str, Any] = {
        "ai": None,
        "ai_error": None,
    }

    raw_data = json.dumps(raw_context, default=str)
    full_prompt = f"{LLM_RCA_PROMPT}\n\nRAW DATA:\n{raw_data}"

    api_url = f"{LLM_API_BASE_URL}/api/generate"
    payload = {
        "model": LLM_MODEL,
        "prompt": full_prompt,
        "stream": False,
        "format": "json",
    }

    try:
        pod_id = f"{raw_context.get('namespace')}/{raw_context.get('pod_name')}"
        print(f"Calling Ollama API ({LLM_MODEL}) for pod {pod_id} ...")
        response = requests.post(
            api_url,
            json=payload,
            timeout=(LLM_CONNECT_TIMEOUT_SECONDS, LLM_READ_TIMEOUT_SECONDS),
        )
        response.raise_for_status()
        body = response.json()

        ai_response_text = body.get("response", "")
        total_duration_ms = body.get("total_duration", 0) // 1_000_000
        print(f"  LLM response complete for {pod_id} ({total_duration_ms}ms)")

        parsed_json: Optional[Dict[str, Any]] = None
        text = ai_response_text.strip()

        if text.startswith("```"):
            lines = text.split("\n")
            if len(lines) > 2:
                text = "\n".join(lines[1:-1])

        try:
            parsed_json = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                parsed_json = json.loads(match.group(0))
            else:
                print(f"Failed to parse LLM JSON response: {text[:500]}")

        result["ai"] = parsed_json
    except requests.exceptions.ConnectionError:
        msg = f"Cannot connect to Ollama at {LLM_API_BASE_URL} — is it running?"
        print(f"Error: {msg}")
        result["ai_error"] = msg
    except Exception as e:
        print(f"Error while calling Ollama API: {e}")
        result["ai_error"] = str(e)

    return result


def collect_unhealthy_pods_with_ai(
    exclude_namespaces: Optional[List[str]] = None,
    skip_ai: bool = False,
) -> Dict[str, Any]:
    """
    Scan cluster for unhealthy pods, collect diagnostics and AI suggestions.
    Returns a dict containing both raw and processed data.
    """
    load_kube_config()
    v1 = client.CoreV1Api()

    pods = v1.list_pod_for_all_namespaces().items
    summaries: List[Dict[str, Any]] = []

    # Start from defaults defined in code/env and extend with explicit arguments
    exclude_set = set(DEFAULT_EXCLUDED_NAMESPACES)
    exclude_set.update(
        ns.strip() for ns in (exclude_namespaces or []) if ns and ns.strip()
    )

    for pod in pods:
        ns = pod.metadata.namespace
        if ns in exclude_set:
            continue

        detection = detect_unhealthy_state(pod)
        if not detection:
            continue

        print(f"Detected unhealthy pod {ns}/{pod.metadata.name}: {detection}")

        context_payload = _build_ai_context_payload(v1, pod, detection)
        if skip_ai:
            llm_result = {"ai": None, "ai_error": "Skipped (--skip-ai)"}
        else:
            llm_result = call_llm_for_context(context_payload)

        # Minimal, fixed-schema summary for clients
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
                "ai": llm_result.get("ai"),
                "ai_error": llm_result.get("ai_error"),
            }
        )

    result: Dict[str, Any] = {
        "timestamp": get_time_now(),
        "cluster_name": CLUSTER_NAME,
        "total_pods_scanned": len(pods),
        "unhealthy_pod_count": len(summaries),
        "unhealthy_pods": summaries,
    }
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Scan Kubernetes cluster for unhealthy pods and get AI-based root cause analysis.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="unhealthy_pods_ai_report.json",
        help="Output file path (JSON). Default: unhealthy_pods_ai_report.json",
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
    parser.add_argument(
        "--skip-ai",
        action="store_true",
        default=False,
        help="Skip LLM API calls; collect diagnostics only.",
    )
    args = parser.parse_args()

    data = collect_unhealthy_pods_with_ai(
        exclude_namespaces=args.exclude_namespace or None,
        skip_ai=args.skip_ai,
    )

    with open(args.output, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"Saved unhealthy pod AI report to {args.output}")


if __name__ == "__main__":
    main()


"""
apiVersion: v1
kind: Pod
metadata:
  name: oom-test
spec:
  containers:
  - name: memory-eater
    image: python:3.9-slim
    command: ["python", "-c", "a = ' ' * (1024 * 1024 * 500)"]
    resources:
      limits:
        memory: "50Mi"
      requests:
        memory: "50Mi"
---
apiVersion: v1
kind: Pod
metadata:
  name: crashloop-test
spec:
  containers:
  - name: crash-container
    image: busybox
    command:
      - sh
      - -c
      - |
        echo "Application starting..."
        sleep 3
        echo "Connecting to database..."
        sleep 2
        echo "ERROR: Database connection failed"
        echo "Application exiting due to fatal error"
        exit 1
---
apiVersion: v1
kind: Pod
metadata:
  name: image-pull-back-off
spec:
  containers:
  - name: test
    image: nginx:this-tag-does-not-exist
---
apiVersion: v1
kind: Pod
metadata:
  name: crashloop-back-off
spec:
  containers:
  - name: crash
    image: busybox
    command: ["sh", "-c", "echo 'App failed'; sleep 2; exit 1"]
---
apiVersion: v1
kind: Pod
metadata:
  name: create-container-config-error
spec:
  containers:
  - name: test
    image: nginx
    env:
    - name: APP_CONFIG
      valueFrom:
        configMapKeyRef:
          name: missing-config
          key: app
---
apiVersion: v1
kind: Pod
metadata:
  name: create-container-error
spec:
  containers:
  - name: test
    image: nginx
    command: ["this-command-does-not-exist"]
---
apiVersion: v1
kind: Pod
metadata:
  name: pending-unschedulable
spec:
  containers:
  - name: test
    image: nginx
    resources:
      requests:
        cpu: "100"
        memory: "500Gi"
---
apiVersion: v1
kind: Pod
metadata:
  name: init-fail-test
spec:
  initContainers:
  - name: init-test
    image: busybox
    command: ["sh","-c","echo init failed; exit 1"]
  containers:
  - name: main
    image: nginx
---
apiVersion: v1
kind: Pod
metadata:
  name: evicted-pods
spec:
  containers:
  - name: test
    image: busybox
    command: ["sh","-c","dd if=/dev/zero of=/tmp/bigfile bs=1M count=20000"]
"""