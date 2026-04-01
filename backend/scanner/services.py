import os
import sys
import threading
from datetime import datetime, timezone
from typing import List, Optional

from bson import ObjectId

from .db import get_db
from .deployment_risk import (
    enrich_deployments_payload,
    merge_scan_params_with_settings,
    merge_secret_scan_params_with_settings,
    get_deployment_scanner_settings_doc,
    save_deployment_scanner_settings_doc,
    get_secret_scanner_settings_doc,
    save_secret_scanner_settings_doc,
    add_ignored_rule,
    remove_ignored_rule,
    get_deployment_detail,
)

SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

def _now():
    return datetime.now(timezone.utc)


def _serialize(doc):
    """Make a MongoDB document JSON-safe (top-level)."""
    if doc is None:
        return None
    doc = dict(doc)
    for key, val in doc.items():
        if isinstance(val, ObjectId):
            doc[key] = str(val)
        elif isinstance(val, datetime):
            doc[key] = val.isoformat()
    return doc


def _maybe_enrich_deployments_scan(doc):
    if not doc or doc.get("scan_type") != "deployments":
        return doc
    if doc.get("status") != "completed" or not doc.get("data"):
        return doc
    db = get_db()
    data = enrich_deployments_payload(doc["data"], db)
    out = dict(doc)
    out["data"] = data
    return out


def _secret_issue_id(finding):
    return f"{finding.get('rule_id', '')}|{finding.get('field_path', '')}"


def _get_secret_ignored_issue_ids(db, namespace, kind, object_name):
    doc = db.secret_leak_ignores.find_one(
        {"namespace": namespace, "kind": kind, "object_name": object_name}
    )
    if not doc:
        return set()
    return set(doc.get("ignored_issue_ids") or [])


def _rebuild_secret_data(filtered_findings):
    sev = {"low": 0, "medium": 0, "high": 0}
    by_ns = {}
    resource_map = {}
    for f in filtered_findings:
        s = f.get("severity", "low")
        ns = f.get("namespace")
        sev[s] = sev.get(s, 0) + 1
        by_ns[ns] = by_ns.get(ns, 0) + 1
        key = (f.get("namespace"), f.get("kind"), f.get("object_name"))
        resource_map.setdefault(key, []).append(f)

    def sev_rank(v):
        return {"high": 3, "medium": 2, "low": 1}.get(v, 0)

    grouped = []
    for (ns, kind, name), items in resource_map.items():
        counts = {"high": 0, "medium": 0, "low": 0}
        max_s = "low"
        issues = []
        for it in sorted(items, key=lambda x: (-sev_rank(x.get("severity")), x.get("field_path", ""))):
            s = it.get("severity", "low")
            counts[s] = counts.get(s, 0) + 1
            if sev_rank(s) > sev_rank(max_s):
                max_s = s
            fp = it.get("field_path", "")
            issues.append(
                {
                    "finding_id": it.get("id"),
                    "issue_id": _secret_issue_id(it),
                    "issue_key": fp.rsplit(".", 1)[-1] if fp else "",
                    "field_path": fp,
                    "severity": s,
                    "rule_id": it.get("rule_id"),
                    "message": it.get("message"),
                    "evidence_masked": it.get("evidence_masked"),
                }
            )
        grouped.append(
            {
                "namespace": ns,
                "kind": kind,
                "object_name": name,
                "total_findings": len(items),
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "max_severity": max_s,
                "issues": issues,
            }
        )
    grouped.sort(
        key=lambda r: (
            -sev_rank(r["max_severity"]),
            -r["high"],
            -r["total_findings"],
            r["namespace"],
            r["kind"],
            r["object_name"],
        )
    )
    object_risk_summary = [
        {
            "namespace": r["namespace"],
            "kind": r["kind"],
            "object_name": r["object_name"],
            "total_findings": r["total_findings"],
            "high": r["high"],
            "medium": r["medium"],
            "low": r["low"],
            "max_severity": r["max_severity"],
        }
        for r in grouped
    ]
    return {
        "total_findings": len(filtered_findings),
        "summary_by_severity": sev,
        "summary_by_namespace": by_ns,
        "object_risk_summary": object_risk_summary,
        "resource_findings": grouped,
        "findings": filtered_findings,
    }


def _maybe_enrich_secrets_scan(doc):
    if not doc or doc.get("scan_type") != "secrets":
        return doc
    if doc.get("status") != "completed" or not doc.get("data"):
        return doc
    from kube_configmap_secret_scanner import (  # noqa: E402
        _normalize_exclude_resource_lines,
        _resource_scan_skipped,
    )

    db = get_db()
    settings = get_secret_scanner_settings_doc(db)
    excluded = _normalize_exclude_resource_lines(
        settings.get("exclude_resources") or []
    )
    data = dict(doc["data"])
    findings = list(data.get("findings") or [])
    filtered = []
    for f in findings:
        if _resource_scan_skipped(
            f.get("kind") or "",
            f.get("namespace") or "",
            f.get("object_name") or "",
            excluded,
        ):
            continue
        ignored = _get_secret_ignored_issue_ids(
            db, f.get("namespace"), f.get("kind"), f.get("object_name")
        )
        if _secret_issue_id(f) in ignored:
            continue
        filtered.append(f)
    rebuilt = _rebuild_secret_data(filtered)
    data["findings"] = rebuilt["findings"]
    data["resource_findings"] = rebuilt["resource_findings"]
    data["summary_by_namespace"] = rebuilt["summary_by_namespace"]
    data["summary_by_severity"] = rebuilt["summary_by_severity"]
    data["object_risk_summary"] = rebuilt["object_risk_summary"]
    data["total_findings"] = rebuilt["total_findings"]
    out = dict(doc)
    out["data"] = data
    return out


def trigger_scan(scan_type, params=None):
    db = get_db()
    doc = {
        "scan_type": scan_type,
        "status": "running",
        "created_at": _now(),
        "completed_at": None,
        "summary": None,
        "data": None,
        "error": None,
    }
    result = db.scan_results.insert_one(doc)
    scan_id = result.inserted_id

    thread = threading.Thread(
        target=_run_scan, args=(scan_id, scan_type, params or {}), daemon=True,
    )
    thread.start()
    return str(scan_id)


def _run_scan(scan_id, scan_type, params):
    db = get_db()
    try:
        from pod_scanner_basic import collect_unhealthy_pods  # noqa: E402
        from kube_configmap_secret_scanner import scan_configmaps_and_secrets  # noqa: E402
        from deployment_risk_scorer import score_deployments  # noqa: E402

        if scan_type == "deployments":
            params = merge_scan_params_with_settings(db, params)

        exclude_ns = params.get("exclude_namespaces")
        if isinstance(exclude_ns, str):
            exclude_ns = [n.strip() for n in exclude_ns.split(",") if n.strip()]

        if scan_type == "pods":
            data = collect_unhealthy_pods(exclude_namespaces=exclude_ns)
            summary = {
                "total_scanned": data.get("total_pods_scanned", 0),
                "unhealthy_count": data.get("unhealthy_pod_count", 0),
            }
        elif scan_type == "secrets":
            params = merge_secret_scan_params_with_settings(db, params)
            exclude_ns = params.get("exclude_namespaces")
            if isinstance(exclude_ns, str):
                exclude_ns = [n.strip() for n in exclude_ns.split(",") if n.strip()]
            data = scan_configmaps_and_secrets(
                exclude_namespaces=exclude_ns,
                exclude_resources=params.get("exclude_resources"),
            )
            sev = data.get("summary_by_severity", {})
            summary = {
                "total_findings": data.get("total_findings", 0),
                "high": sev.get("high", 0),
                "medium": sev.get("medium", 0),
                "low": sev.get("low", 0),
            }
        elif scan_type == "deployments":
            data = score_deployments(
                exclude_namespaces=exclude_ns,
                skip_workloads=params.get("skip_workloads"),
                enable_trivy=params.get("enable_trivy", False),
            )
            summary = {
                "total_scored": data.get("total_deployments_scored", 0),
                "average_score": data.get("average_score", 0),
                "risk_distribution": data.get("risk_distribution", {}),
            }
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

        db.scan_results.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "completed",
                "completed_at": _now(),
                "summary": summary,
                "data": data,
            }},
        )
    except Exception as exc:
        db.scan_results.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "failed",
                "completed_at": _now(),
                "error": str(exc),
            }},
        )


def get_scan(scan_id):
    db = get_db()
    try:
        doc = db.scan_results.find_one({"_id": ObjectId(scan_id)})
    except Exception:
        return None
    doc = _maybe_enrich_deployments_scan(doc)
    doc = _maybe_enrich_secrets_scan(doc)
    return _serialize(doc)


def list_scans(limit=50):
    db = get_db()
    cursor = (
        db.scan_results
        .find({}, {"data": 0})
        .sort("created_at", -1)
        .limit(limit)
    )
    return [_serialize(doc) for doc in cursor]


def get_latest_scan(scan_type):
    db = get_db()
    doc = db.scan_results.find_one(
        {"scan_type": scan_type, "status": "completed"},
        sort=[("created_at", -1)],
    )
    doc = _maybe_enrich_deployments_scan(doc)
    doc = _maybe_enrich_secrets_scan(doc)
    return _serialize(doc)


def get_dashboard():
    db = get_db()
    total_scans = db.scan_results.count_documents({})
    latest = {}
    for stype in ("pods", "secrets", "deployments"):
        scan = get_latest_scan(stype)
        if scan:
            latest[stype] = {
                "scan_id": scan["_id"],
                "created_at": scan.get("created_at"),
                "status": scan.get("status"),
                "summary": scan.get("summary"),
            }
    return {"total_scans": total_scans, "latest": latest}


def get_scanner_settings():
    return get_deployment_scanner_settings_doc(get_db())


def save_scanner_settings(exclude_namespaces, skip_workloads):
    if isinstance(exclude_namespaces, str):
        exclude_namespaces = [x.strip() for x in exclude_namespaces.split(",") if x.strip()]
    if isinstance(skip_workloads, str):
        skip_workloads = [x.strip() for x in skip_workloads.split(",") if x.strip()]
    return save_deployment_scanner_settings_doc(
        get_db(),
        list(exclude_namespaces or []),
        list(skip_workloads or []),
    )


def get_secret_scanner_settings():
    return get_secret_scanner_settings_doc(get_db())


def save_secret_scanner_settings(
    exclude_namespaces: Optional[List[str]] = None,
    exclude_resources: Optional[List[str]] = None,
):
    if isinstance(exclude_namespaces, str):
        exclude_namespaces = [x.strip() for x in exclude_namespaces.split(",") if x.strip()]
    if isinstance(exclude_resources, str):
        exclude_resources = [x.strip() for x in exclude_resources.split(",") if x.strip()]
    return save_secret_scanner_settings_doc(
        get_db(),
        list(exclude_namespaces or []),
        list(exclude_resources or []),
    )


def deployment_detail(namespace, deployment):
    return get_deployment_detail(get_db(), namespace, deployment)


def ignore_deployment_rule(namespace, deployment, rule):
    rules = add_ignored_rule(get_db(), namespace, deployment, rule)
    return {"ignored_rules": rules}


def unignore_deployment_rule(namespace, deployment, rule):
    rules = remove_ignored_rule(get_db(), namespace, deployment, rule)
    return {"ignored_rules": rules}


def ignore_secret_issue(namespace, kind, object_name, issue_id):
    db = get_db()
    db.secret_leak_ignores.update_one(
        {"namespace": namespace, "kind": kind, "object_name": object_name},
        {
            "$addToSet": {"ignored_issue_ids": issue_id},
            "$set": {"updated_at": _now()},
            "$setOnInsert": {
                "namespace": namespace,
                "kind": kind,
                "object_name": object_name,
            },
        },
        upsert=True,
    )
    return {"ok": True}


def unignore_secret_issue(namespace, kind, object_name, issue_id):
    db = get_db()
    db.secret_leak_ignores.update_one(
        {"namespace": namespace, "kind": kind, "object_name": object_name},
        {"$pull": {"ignored_issue_ids": issue_id}, "$set": {"updated_at": _now()}},
    )
    return {"ok": True}


def ignore_secret_resource(namespace, kind, object_name):
    current = get_secret_scanner_settings()
    k = kind.lower()
    token = f"{k}:{namespace}/{object_name}"
    resources = list(current.get("exclude_resources") or [])
    if token not in resources:
        resources.append(token)
    saved = save_secret_scanner_settings(
        current.get("exclude_namespaces") or [],
        resources,
    )
    return saved


def unignore_secret_resource(namespace, kind, object_name):
    current = get_secret_scanner_settings()
    k = kind.lower()
    token = f"{k}:{namespace}/{object_name}"
    resources = [
        r for r in (current.get("exclude_resources") or []) if r != token
    ]
    return save_secret_scanner_settings(
        current.get("exclude_namespaces") or [],
        resources,
    )


def get_secret_leak_ignores_overview():
    """Excluded whole resources + per-issue ignores for the Secret Leakage UI."""
    db = get_db()
    settings = get_secret_scanner_settings_doc(db)
    excluded = list(settings.get("exclude_resources") or [])
    ignored_issues = []
    for doc in db.secret_leak_ignores.find({}):
        ids = list(doc.get("ignored_issue_ids") or [])
        if not ids:
            continue
        ignored_issues.append(
            {
                "namespace": doc.get("namespace"),
                "kind": doc.get("kind"),
                "object_name": doc.get("object_name"),
                "ignored_issue_ids": ids,
            }
        )
    ignored_issues.sort(
        key=lambda x: (x["namespace"] or "", x["kind"] or "", x["object_name"] or "")
    )
    return {"excluded_resources": excluded, "ignored_issues": ignored_issues}
