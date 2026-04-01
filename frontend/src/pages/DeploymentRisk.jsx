import { useEffect, useState, useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import { getLatestScan, triggerScan, pollScan } from "../api";

function RiskBadge({ level }) {
  const cls = {
    Critical: "bg-red-100 text-red-700",
    High: "bg-orange-100 text-orange-700",
    Medium: "bg-amber-100 text-amber-700",
    Low: "bg-green-100 text-green-700",
  }[level] || "bg-gray-100 text-gray-600";
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls}`}>
      {level}
    </span>
  );
}

function ScoreBar({ score }) {
  const color =
    score >= 80
      ? "bg-green-500"
      : score >= 60
      ? "bg-amber-500"
      : score >= 40
      ? "bg-orange-500"
      : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-2 bg-gray-200 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className="text-sm font-semibold">{score}</span>
    </div>
  );
}

export default function DeploymentRisk() {
  const [scan, setScan] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [nsFilter, setNsFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [sortBy, setSortBy] = useState("effective_desc");

  const load = useCallback(() => {
    getLatestScan("deployments")
      .then(setScan)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(load, [load]);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { scan_id } = await triggerScan("deployments");
      pollScan(scan_id, (data) => {
        if (data?.status !== "running") {
          setScanning(false);
          if (data?.status === "completed") setScan(data);
          else if (data?.status === "failed")
            setError(data.error || "Scan failed");
        }
      });
    } catch (e) {
      setScanning(false);
      setError(e.message);
    }
  };

  const deps = scan?.data?.deployments || [];
  const dist = scan?.data?.risk_distribution || {};

  const namespaces = useMemo(() => {
    const s = new Set(deps.map((d) => d.namespace));
    return Array.from(s).sort();
  }, [deps]);

  const filteredSorted = useMemo(() => {
    let list = [...deps];
    const q = nsFilter.trim().toLowerCase();
    if (q) {
      list = list.filter((d) => d.namespace.toLowerCase().includes(q));
    }
    if (riskFilter) {
      list = list.filter((d) => d.risk_level === riskFilter);
    }
    list.sort((a, b) => {
      switch (sortBy) {
        case "effective_asc":
          return (a.effective_score ?? a.score) - (b.effective_score ?? b.score);
        case "effective_desc":
          return (b.effective_score ?? b.score) - (a.effective_score ?? a.score);
        case "raw_desc":
          return (b.raw_score ?? b.score) - (a.raw_score ?? a.score);
        case "name_asc":
          return a.deployment.localeCompare(b.deployment);
        case "namespace_asc":
          return a.namespace.localeCompare(b.namespace);
        default:
          return 0;
      }
    });
    return list;
  }, [deps, nsFilter, riskFilter, sortBy]);

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h2 className="text-2xl font-bold">Deployment Risk Scores</h2>
          {scan?.created_at && (
            <p className="text-xs text-gray-400 mt-1">
              Last scan: {new Date(scan.created_at).toLocaleString()}
              {scan.data?.average_effective_score != null && (
                <span className="ml-2">
                  · Avg effective:{" "}
                  <strong>{scan.data.average_effective_score}</strong>
                  {scan.data.average_score != null && (
                    <span className="text-gray-400">
                      {" "}
                      (raw {scan.data.average_score})
                    </span>
                  )}
                </span>
              )}
            </p>
          )}
        </div>
        <button
          onClick={runScan}
          disabled={scanning}
          className="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {scanning ? "Scoring…" : "Run Scan"}
        </button>
      </div>

      <p className="text-sm text-gray-600 mb-4">
        Each scan is stored in MongoDB. Run scans over time to build a score
        trend per workload. Ignored rules (from the detail page) raise the
        effective score without changing raw scanner output.
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
          <div className="grid grid-cols-4 gap-4 mb-6">
            {["Critical", "High", "Medium", "Low"].map((level) => {
              const colors = {
                Critical: "text-red-600",
                High: "text-orange-600",
                Medium: "text-amber-600",
                Low: "text-green-600",
              };
              return (
                <div
                  key={level}
                  className="bg-white rounded-xl shadow-sm border border-gray-200 p-4 text-center"
                >
                  <p className="text-xs uppercase text-gray-500 mb-1">
                    {level}
                  </p>
                  <p className={`text-2xl font-bold ${colors[level]}`}>
                    {dist[level] ?? 0}
                  </p>
                </div>
              );
            })}
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4 mb-4 flex flex-wrap gap-4 items-end">
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">
                Namespace contains
              </label>
              <input
                type="text"
                list="ns-suggest"
                value={nsFilter}
                onChange={(e) => setNsFilter(e.target.value)}
                placeholder="e.g. prod"
                className="border border-gray-300 rounded-lg px-3 py-2 text-sm w-48"
              />
              <datalist id="ns-suggest">
                {namespaces.map((n) => (
                  <option key={n} value={n} />
                ))}
              </datalist>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">
                Risk (effective)
              </label>
              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                className="border border-gray-300 rounded-lg px-3 py-2 text-sm"
              >
                <option value="">All</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">
                Sort
              </label>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="border border-gray-300 rounded-lg px-3 py-2 text-sm"
              >
                <option value="effective_desc">Effective score ↓</option>
                <option value="effective_asc">Effective score ↑</option>
                <option value="raw_desc">Raw score ↓</option>
                <option value="name_asc">Name A–Z</option>
                <option value="namespace_asc">Namespace A–Z</option>
              </select>
            </div>
            <p className="text-sm text-gray-500 pb-2">
              Showing {filteredSorted.length} of {deps.length}
            </p>
          </div>

          {deps.length > 0 && (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
                  <tr>
                    <th className="px-4 py-3 text-left">Deployment</th>
                    <th className="px-4 py-3 text-left">Namespace</th>
                    <th className="px-4 py-3 text-left">Effective</th>
                    <th className="px-4 py-3 text-left">Raw</th>
                    <th className="px-4 py-3 text-left">Risk</th>
                    <th className="px-4 py-3 text-right">Replicas</th>
                    <th className="px-4 py-3 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {filteredSorted.map((d, i) => (
                    <tr key={`${d.namespace}/${d.deployment}`} className="hover:bg-gray-50">
                      <td className="px-4 py-3 font-medium">{d.deployment}</td>
                      <td className="px-4 py-3 text-gray-500">{d.namespace}</td>
                      <td className="px-4 py-3">
                        <ScoreBar score={d.effective_score ?? d.score} />
                      </td>
                      <td className="px-4 py-3 text-gray-500">
                        {d.raw_score ?? d.score}
                      </td>
                      <td className="px-4 py-3">
                        <RiskBadge level={d.risk_level} />
                      </td>
                      <td className="px-4 py-3 text-right">
                        {d.replicas ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          to={`/deployment-risk/${encodeURIComponent(d.namespace)}/${encodeURIComponent(d.deployment)}`}
                          className="text-indigo-600 hover:underline font-medium"
                        >
                          Open
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
