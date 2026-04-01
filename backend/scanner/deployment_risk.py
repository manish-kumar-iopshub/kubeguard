"""Deployment risk: effective scores, ignores, history, scanner settings."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Set

SETTINGS_DOC_ID = "default"


def risk_level_for_score(score: int) -> str:
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def effective_score_and_deductions(
    dep: Dict[str, Any], ignored_rules: Set[str]
) -> Dict[str, Any]:
    deductions = list(dep.get("deductions") or [])
    raw_score = int(dep.get("score", 100))
    active_weights = sum(
        d["weight"] for d in deductions if d.get("rule") not in ignored_rules
    )
    effective = max(0, 100 + active_weights)
    display = []
    for d in deductions:
        r = d.get("rule")
        display.append({**d, "ignored": r in ignored_rules})
    display.sort(key=lambda x: (not x["ignored"], x.get("category", ""), x.get("rule", "")))
    return {
        **dep,
        "raw_score": raw_score,
        "effective_score": effective,
        "score": effective,
        "risk_level": risk_level_for_score(effective),
        "raw_risk_level": risk_level_for_score(raw_score),
        "deductions": display,
    }


def enrich_deployments_payload(data: Dict[str, Any], db) -> Dict[str, Any]:
    if not data or "deployments" not in data:
        return data
    out = dict(data)
    enriched = []
    for dep in data["deployments"]:
        ns = dep.get("namespace")
        name = dep.get("deployment")
        ignored = get_ignored_rules(db, ns, name)
        enriched.append(effective_score_and_deductions(dep, ignored))
    out["deployments"] = enriched
    if enriched:
        out["average_effective_score"] = round(
            sum(d["effective_score"] for d in enriched) / len(enriched), 1
        )
    else:
        out["average_effective_score"] = 0
    return out


def get_ignored_rules(db, namespace: str, deployment: str) -> Set[str]:
    doc = db.deployment_ignores.find_one(
        {"namespace": namespace, "deployment": deployment}
    )
    if not doc:
        return set()
    return set(doc.get("ignored_rules") or [])


def add_ignored_rule(db, namespace: str, deployment: str, rule: str) -> List[str]:
    db.deployment_ignores.update_one(
        {"namespace": namespace, "deployment": deployment},
        {
            "$addToSet": {"ignored_rules": rule},
            "$set": {"updated_at": datetime.now(timezone.utc)},
            "$setOnInsert": {
                "namespace": namespace,
                "deployment": deployment,
            },
        },
        upsert=True,
    )
    return sorted(get_ignored_rules(db, namespace, deployment))


def remove_ignored_rule(db, namespace: str, deployment: str, rule: str) -> List[str]:
    db.deployment_ignores.update_one(
        {"namespace": namespace, "deployment": deployment},
        {
            "$pull": {"ignored_rules": rule},
            "$set": {"updated_at": datetime.now(timezone.utc)},
        },
    )
    return sorted(get_ignored_rules(db, namespace, deployment))


def get_scanner_settings_doc(db) -> Dict[str, Any]:
    doc = db.scanner_settings.find_one({"_id": SETTINGS_DOC_ID})
    if not doc:
        return {
            "exclude_namespaces": [],
            "skip_workloads": [],
        }
    return {
        "exclude_namespaces": list(doc.get("exclude_namespaces") or []),
        "skip_workloads": list(doc.get("skip_workloads") or []),
    }


def save_scanner_settings_doc(
    db, exclude_namespaces: List[str], skip_workloads: List[str]
) -> Dict[str, Any]:
    db.scanner_settings.update_one(
        {"_id": SETTINGS_DOC_ID},
        {
            "$set": {
                "exclude_namespaces": exclude_namespaces,
                "skip_workloads": skip_workloads,
                "updated_at": datetime.now(timezone.utc),
            },
            "$setOnInsert": {"_id": SETTINGS_DOC_ID},
        },
        upsert=True,
    )
    return get_scanner_settings_doc(db)


def merge_scan_params_with_settings(db, params: Dict[str, Any]) -> Dict[str, Any]:
    settings = get_scanner_settings_doc(db)
    merged = dict(params)
    req_exclude = merged.get("exclude_namespaces")
    if isinstance(req_exclude, str):
        req_exclude = [x.strip() for x in req_exclude.split(",") if x.strip()]
    elif req_exclude is None:
        req_exclude = []
    merged["exclude_namespaces"] = list(
        {*(settings.get("exclude_namespaces") or []), *req_exclude}
    )
    req_skip = merged.get("skip_workloads")
    if isinstance(req_skip, str):
        req_skip = [x.strip() for x in req_skip.split(",") if x.strip()]
    elif req_skip is None:
        req_skip = []
    merged["skip_workloads"] = list(
        {*(settings.get("skip_workloads") or []), *req_skip}
    )
    return merged


def build_deployment_history(
    db, namespace: str, deployment: str, limit: int = 80
) -> List[Dict[str, Any]]:
    ignored = get_ignored_rules(db, namespace, deployment)
    cursor = (
        db.scan_results.find(
            {"scan_type": "deployments", "status": "completed"},
            {"created_at": 1, "data.deployments": 1},
        )
        .sort("created_at", -1)
        .limit(limit)
    )
    rows = list(cursor)
    rows.reverse()
    history: List[Dict[str, Any]] = []
    prev_rules: Set[str] = set()
    for doc in rows:
        deps = (doc.get("data") or {}).get("deployments") or []
        match = next(
            (
                d
                for d in deps
                if d.get("namespace") == namespace and d.get("deployment") == deployment
            ),
            None,
        )
        if not match:
            continue
        raw = int(match.get("score", 100))
        deds = list(match.get("deductions") or [])
        eff = max(
            0,
            100
            + sum(d["weight"] for d in deds if d.get("rule") not in ignored),
        )
        rules_now = {d.get("rule") for d in deds if d.get("rule")}
        added = sorted(rules_now - prev_rules)
        removed = sorted(prev_rules - rules_now)
        prev_rules = rules_now
        ts = doc["created_at"]
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()
        else:
            ts = str(ts)
        history.append(
            {
                "scan_id": str(doc["_id"]),
                "created_at": ts,
                "raw_score": raw,
                "effective_score": eff,
                "open_findings": len(deds),
                "rules": sorted(rules_now),
                "rules_added_vs_previous": added,
                "rules_removed_vs_previous": removed,
            }
        )
    return history


def get_deployment_detail(db, namespace: str, deployment: str) -> Dict[str, Any]:
    latest = db.scan_results.find_one(
        {"scan_type": "deployments", "status": "completed"},
        sort=[("created_at", -1)],
    )
    if not latest:
        return {"error": "No completed deployment scans"}
    deps = (latest.get("data") or {}).get("deployments") or []
    dep = next(
        (
            d
            for d in deps
            if d.get("namespace") == namespace and d.get("deployment") == deployment
        ),
        None,
    )
    if not dep:
        return {"error": "Deployment not found in latest scan"}
    ignored = get_ignored_rules(db, namespace, deployment)
    enriched = effective_score_and_deductions(dep, ignored)
    history = build_deployment_history(db, namespace, deployment)
    lat = latest["created_at"]
    if hasattr(lat, "isoformat"):
        lat = lat.isoformat()
    else:
        lat = str(lat)
    return {
        "latest_scan_id": str(latest["_id"]),
        "latest_scan_at": lat,
        "ignored_rules": sorted(ignored),
        "workload": enriched,
        "history": history,
    }
