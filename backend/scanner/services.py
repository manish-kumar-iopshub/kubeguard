import os
import sys
import threading
from datetime import datetime, timezone

from bson import ObjectId

from .db import get_db

SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from pod_scanner_basic import collect_unhealthy_pods  # noqa: E402
from kube_configmap_secret_scanner import scan_configmaps_and_secrets  # noqa: E402
from deployment_risk_scorer import score_deployments  # noqa: E402


def _now():
    return datetime.now(timezone.utc)


def _serialize(doc):
    """Make a MongoDB document JSON-safe."""
    if doc is None:
        return None
    doc = dict(doc)
    for key, val in doc.items():
        if isinstance(val, ObjectId):
            doc[key] = str(val)
        elif isinstance(val, datetime):
            doc[key] = val.isoformat()
    return doc


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
            data = scan_configmaps_and_secrets(exclude_namespaces=exclude_ns)
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
