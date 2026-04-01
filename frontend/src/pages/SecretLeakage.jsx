import { useEffect, useState, useCallback, useMemo, Fragment } from "react";
import { Link } from "react-router-dom";
import {
  getLatestScan,
  triggerScan,
  pollScan,
  ignoreSecretIssue,
  ignoreSecretResource,
  unignoreSecretResource,
  unignoreSecretIssue,
  getSecretLeakIgnores,
} from "../api";

/** Parses tokens like `configmap:ns/name` saved by the backend. */
function parseSecretExcludeToken(token) {
  if (!token || typeof token !== "string") return null;
  const colon = token.indexOf(":");
  if (colon < 0) return null;
  const kindRaw = token.slice(0, colon).trim().toLowerCase();
  const rest = token.slice(colon + 1).trim();
  const slash = rest.indexOf("/");
  if (slash < 0) return null;
  const namespace = rest.slice(0, slash);
  const object_name = rest.slice(slash + 1);
  const kind =
    kindRaw === "configmap"
      ? "ConfigMap"
      : kindRaw === "secret"
      ? "Secret"
      : kindRaw;
  return { namespace, kind, object_name };
}

function SeverityBadge({ severity }) {
  const cls = {
    high: "bg-red-100 text-red-700",
    medium: "bg-amber-100 text-amber-700",
    low: "bg-blue-100 text-blue-700",
  }[severity] || "bg-gray-100 text-gray-600";
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls}`}>
      {severity}
    </span>
  );
}

const SEV_ORDER = { high: 3, medium: 2, low: 1 };

function clientGroupFindings(findings) {
  if (!findings?.length) return [];
  const map = new Map();
  for (const f of findings) {
    const key = JSON.stringify([f.namespace, f.kind, f.object_name]);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(f);
  }
  const rows = [];
  for (const items of map.values()) {
    const f0 = items[0];
    const high = items.filter((x) => x.severity === "high").length;
    const medium = items.filter((x) => x.severity === "medium").length;
    const low = items.filter((x) => x.severity === "low").length;
    let max_severity = "low";
    for (const x of items) {
      const s = x.severity || "low";
      if ((SEV_ORDER[s] || 0) > (SEV_ORDER[max_severity] || 0)) max_severity = s;
    }
    const fpLast = (fp) => (fp || "").split(".").pop() || "";
    const issues = [...items]
      .sort(
        (a, b) =>
          (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0) ||
          (a.field_path || "").localeCompare(b.field_path || "")
      )
      .map((it) => ({
        finding_id: it.id,
        issue_id: `${it.rule_id || ""}|${it.field_path || ""}`,
        issue_key: fpLast(it.field_path),
        field_path: it.field_path,
        severity: it.severity,
        rule_id: it.rule_id,
        message: it.message,
        evidence_masked: it.evidence_masked,
      }));
    rows.push({
      namespace: f0.namespace,
      kind: f0.kind,
      object_name: f0.object_name,
      total_findings: items.length,
      high,
      medium,
      low,
      max_severity,
      issues,
    });
  }
  rows.sort(
    (a, b) =>
      (SEV_ORDER[b.max_severity] || 0) - (SEV_ORDER[a.max_severity] || 0) ||
      b.high - a.high ||
      b.total_findings - a.total_findings ||
      a.namespace.localeCompare(b.namespace)
  );
  return rows;
}

function MaxSeverityBadge({ level }) {
  const cls = {
    high: "bg-red-100 text-red-800 border border-red-200",
    medium: "bg-amber-100 text-amber-800 border border-amber-200",
    low: "bg-blue-100 text-blue-800 border border-blue-200",
  }[level] || "bg-gray-100 text-gray-600";
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>
      {level}
    </span>
  );
}

export default function SecretLeakage() {
  const [scan, setScan] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [openResource, setOpenResource] = useState({});
  const [openIssueKeys, setOpenIssueKeys] = useState({});
  const [busy, setBusy] = useState("");
  const [ignoresOverview, setIgnoresOverview] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const s = await getLatestScan("secrets");
      setScan(s);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
    try {
      const ign = await getSecretLeakIgnores();
      setIgnoresOverview(ign);
    } catch {
      setIgnoresOverview({ excluded_resources: [], ignored_issues: [] });
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { scan_id } = await triggerScan("secrets");
      pollScan(scan_id, (data) => {
        if (data?.status !== "running") {
          setScanning(false);
          if (data?.status === "completed") {
            setScan(data);
            getSecretLeakIgnores().then(setIgnoresOverview).catch(() => {});
          } else if (data?.status === "failed")
            setError(data.error || "Scan failed");
        }
      });
    } catch (e) {
      setScanning(false);
      setError(e.message);
    }
  };

  const severity = scan?.data?.summary_by_severity || {};
  const appliedExcludes = scan?.data?.exclude_resources || [];

  const resourceRows = useMemo(() => {
    const fromApi = scan?.data?.resource_findings;
    if (fromApi?.length) return fromApi;
    return clientGroupFindings(scan?.data?.findings);
  }, [scan]);

  const rowKeys = useMemo(
    () => resourceRows.map((r) => `${r.namespace}|${r.kind}|${r.object_name}`),
    [resourceRows]
  );

  const toggleRes = (key) => {
    setOpenResource((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const onIgnoreResource = async (r) => {
    setBusy(`res:${r.namespace}:${r.kind}:${r.object_name}`);
    try {
      await ignoreSecretResource(r.namespace, r.kind, r.object_name);
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const onIgnoreIssue = async (r, issue) => {
    setBusy(`iss:${issue.issue_id}`);
    try {
      await ignoreSecretIssue(r.namespace, r.kind, r.object_name, issue.issue_id);
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const onRestoreExcludedResource = async (token) => {
    const parsed = parseSecretExcludeToken(token);
    if (!parsed) {
      setError("Could not parse excluded resource token.");
      return;
    }
    setBusy(`restore-res:${token}`);
    try {
      await unignoreSecretResource(
        parsed.namespace,
        parsed.kind,
        parsed.object_name
      );
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const onRestoreIgnoredIssue = async (row, issueId) => {
    setBusy(`restore-iss:${issueId}`);
    try {
      await unignoreSecretIssue(row.namespace, row.kind, row.object_name, issueId);
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  };

  const excludedList = ignoresOverview?.excluded_resources ?? [];
  const ignoredIssueGroups = ignoresOverview?.ignored_issues ?? [];
  const hasIgnoredSection =
    ignoresOverview != null &&
    (excludedList.length > 0 || ignoredIssueGroups.length > 0);

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-2xl font-bold">Secret Leakage Scanner</h2>
          {scan?.created_at && (
            <p className="text-xs text-gray-400 mt-1">
              Last scan: {new Date(scan.created_at).toLocaleString()}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <Link
            to="/settings"
            className="text-sm text-indigo-600 hover:underline font-medium"
          >
            Exclusions & settings
          </Link>
          <button
            onClick={runScan}
            disabled={scanning}
            className="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {scanning ? "Scanning…" : "Run Scan"}
          </button>
        </div>
      </div>

      <p className="text-sm text-gray-600 mb-4">
        Results are grouped by ConfigMap or Secret. Expand a row to see how many
        findings and which <strong>keys / field paths</strong> triggered rules. Secret
        scanner exclusions are stored separately from deployment risk (see Settings).
      </p>

      {error && (
        <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg text-sm">
          {error}
        </div>
      )}

      {!scan && !error && (
        <p className="text-gray-400 text-center py-16">
          No scan results yet. Click "Run Scan" to start.
        </p>
      )}

      {scan && (
        <>
          <div className="grid grid-cols-3 gap-4 mb-6">
            {["high", "medium", "low"].map((s) => (
              <div
                key={s}
                className="bg-white rounded-xl shadow-sm border border-gray-200 p-4 text-center"
              >
                <p className="text-xs uppercase text-gray-500 mb-1">{s}</p>
                <p
                  className={`text-2xl font-bold ${
                    s === "high"
                      ? "text-red-600"
                      : s === "medium"
                      ? "text-amber-600"
                      : "text-blue-600"
                  }`}
                >
                  {severity[s] ?? 0}
                </p>
              </div>
            ))}
          </div>

          {appliedExcludes.length > 0 && (
            <div className="mb-4 text-xs text-gray-500 bg-gray-100 rounded-lg px-3 py-2">
              <span className="font-semibold text-gray-600">
                Resources excluded this run:
              </span>{" "}
              {appliedExcludes.join(", ")}
            </div>
          )}

          {resourceRows.length === 0 ? (
            <div className="text-center py-16 text-green-600">
              <p className="text-3xl mb-2">✓</p>
              <p className="font-semibold">No secret leakage detected</p>
            </div>
          ) : (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
                  <tr>
                    <th className="px-4 py-3 text-left w-8" />
                    <th className="px-4 py-3 text-left">Kind</th>
                    <th className="px-4 py-3 text-left">Namespace / Name</th>
                    <th className="px-4 py-3 text-left">Max severity</th>
                    <th className="px-4 py-3 text-right">Findings</th>
                    <th className="px-4 py-3 text-right">H / M / L</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {resourceRows.map((r, idx) => {
                    const rkey = rowKeys[idx];
                    const expanded = openResource[rkey];
                    return (
                      <Fragment key={rkey}>
                        <tr
                          className="hover:bg-gray-50 cursor-pointer"
                          onClick={() => toggleRes(rkey)}
                        >
                          <td className="px-4 py-3 text-gray-400">
                            {expanded ? "▾" : "▸"}
                          </td>
                          <td className="px-4 py-3 font-medium">{r.kind}</td>
                          <td className="px-4 py-3 text-gray-700">
                            <span className="text-gray-400">{r.namespace}/</span>
                            {r.object_name}
                          </td>
                          <td className="px-4 py-3">
                            <MaxSeverityBadge level={r.max_severity} />
                          </td>
                          <td className="px-4 py-3 text-right font-semibold">
                            {r.total_findings}
                          </td>
                          <td className="px-4 py-3 text-right text-gray-500 text-xs">
                            {r.high} / {r.medium} / {r.low}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                onIgnoreResource(r);
                              }}
                              disabled={busy === `res:${r.namespace}:${r.kind}:${r.object_name}`}
                              className="text-xs px-2 py-1 rounded bg-gray-800 text-white hover:bg-gray-700 disabled:opacity-50"
                            >
                              Ignore {r.kind}
                            </button>
                          </td>
                        </tr>
                        {expanded && (
                          <tr>
                            <td colSpan={7} className="px-6 py-4 bg-gray-50">
                              <p className="text-xs font-semibold text-gray-600 mb-3">
                                Issues by key / field ({r.issues?.length || 0})
                              </p>
                              <div className="space-y-2">
                                {(r.issues || []).map((issue, j) => {
                                  const ik = `${rkey}-${j}`;
                                  const show = openIssueKeys[ik];
                                  return (
                                    <div
                                      key={ik}
                                      className="border border-gray-200 rounded-lg bg-white overflow-hidden"
                                    >
                                      <button
                                        type="button"
                                        className="w-full text-left px-3 py-2 flex flex-wrap items-center gap-2 hover:bg-gray-50"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setOpenIssueKeys((prev) => ({
                                            ...prev,
                                            [ik]: !prev[ik],
                                          }));
                                        }}
                                      >
                                        <span className="text-gray-400 text-xs">
                                          {show ? "▾" : "▸"}
                                        </span>
                                        <SeverityBadge severity={issue.severity} />
                                        <code className="text-xs bg-gray-100 px-1.5 py-0.5 rounded">
                                          {issue.issue_key || "(metadata)"}
                                        </code>
                                        <span className="text-xs text-gray-500 font-mono">
                                          {issue.field_path}
                                        </span>
                                        <span className="text-xs text-amber-700 font-mono">
                                          {issue.rule_id}
                                        </span>
                                        <span className="ml-auto">
                                          <button
                                            type="button"
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              onIgnoreIssue(r, issue);
                                            }}
                                            disabled={busy === `iss:${issue.issue_id}`}
                                            className="text-xs px-2 py-1 rounded bg-gray-800 text-white hover:bg-gray-700 disabled:opacity-50"
                                          >
                                            Ignore leak
                                          </button>
                                        </span>
                                      </button>
                                      {show && (
                                        <div className="px-3 pb-3 pt-0 text-xs border-t border-gray-100">
                                          <p className="text-gray-700 mt-2">
                                            {issue.message}
                                          </p>
                                          {issue.evidence_masked && (
                                            <p className="mt-1 text-gray-400 font-mono">
                                              Evidence: {issue.evidence_masked}
                                            </p>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div className="mt-10 border-t border-gray-200 pt-8">
            <h3 className="text-lg font-semibold text-gray-800 mb-2">
              Ignored risks
            </h3>
            <p className="text-sm text-gray-600 mb-4">
              Whole ConfigMaps/Secrets excluded from scans, and individual leak
              ignores. Restore to show them again in the table above (after
              refresh; no re-scan required for excludes).
            </p>
            {ignoresOverview && !hasIgnoredSection && (
              <p className="text-sm text-gray-400 italic">
                Nothing ignored yet.
              </p>
            )}
            {excludedList.length > 0 && (
              <div className="mb-6">
                <h4 className="text-xs font-semibold uppercase text-gray-500 mb-2">
                  Ignored resources
                </h4>
                <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
                      <tr>
                        <th className="px-4 py-2 text-left">Exclude token</th>
                        <th className="px-4 py-2 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {excludedList.map((token) => (
                        <tr key={token}>
                          <td className="px-4 py-2 font-mono text-xs">
                            {token}
                          </td>
                          <td className="px-4 py-2 text-right">
                            <button
                              type="button"
                              onClick={() => onRestoreExcludedResource(token)}
                              disabled={busy === `restore-res:${token}`}
                              className="text-xs px-2 py-1 rounded bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"
                            >
                              Restore as risk
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            {ignoredIssueGroups.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold uppercase text-gray-500 mb-2">
                  Ignored leaks (per issue)
                </h4>
                <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
                      <tr>
                        <th className="px-4 py-2 text-left">Resource</th>
                        <th className="px-4 py-2 text-left">Issue id</th>
                        <th className="px-4 py-2 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {ignoredIssueGroups.flatMap((row) =>
                        (row.ignored_issue_ids || []).map((issueId) => (
                          <tr
                            key={`${row.namespace}|${row.kind}|${row.object_name}|${issueId}`}
                          >
                            <td className="px-4 py-2">
                              <span className="font-medium">{row.kind}</span>{" "}
                              <span className="text-gray-500">
                                {row.namespace}/{row.object_name}
                              </span>
                            </td>
                            <td className="px-4 py-2 font-mono text-xs break-all">
                              {issueId}
                            </td>
                            <td className="px-4 py-2 text-right">
                              <button
                                type="button"
                                onClick={() =>
                                  onRestoreIgnoredIssue(row, issueId)
                                }
                                disabled={busy === `restore-iss:${issueId}`}
                                className="text-xs px-2 py-1 rounded bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"
                              >
                                Restore
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
