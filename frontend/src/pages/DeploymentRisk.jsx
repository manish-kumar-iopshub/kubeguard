import { useEffect, useState, useCallback } from "react";
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
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState(null);

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

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold">Deployment Risk Scores</h2>
          {scan?.created_at && (
            <p className="text-xs text-gray-400 mt-1">
              Last scan: {new Date(scan.created_at).toLocaleString()}
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

          <div className="mb-3 text-sm text-gray-500">
            Average score:{" "}
            <span className="font-bold text-gray-800">
              {scan.data?.average_score ?? "—"}
            </span>{" "}
            / 100 across {deps.length} deployments
          </div>

          {deps.length > 0 && (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
                  <tr>
                    <th className="px-4 py-3 text-left">Deployment</th>
                    <th className="px-4 py-3 text-left">Namespace</th>
                    <th className="px-4 py-3 text-left">Score</th>
                    <th className="px-4 py-3 text-left">Risk</th>
                    <th className="px-4 py-3 text-right">Replicas</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {deps.map((d, i) => (
                    <>
                      <tr
                        key={i}
                        className="hover:bg-gray-50 cursor-pointer"
                        onClick={() =>
                          setExpanded((prev) => ({ ...prev, [i]: !prev[i] }))
                        }
                      >
                        <td className="px-4 py-3 font-medium">
                          <span className="mr-1 text-gray-400">
                            {expanded[i] ? "▾" : "▸"}
                          </span>
                          {d.deployment}
                        </td>
                        <td className="px-4 py-3 text-gray-500">
                          {d.namespace}
                        </td>
                        <td className="px-4 py-3">
                          <ScoreBar score={d.score} />
                        </td>
                        <td className="px-4 py-3">
                          <RiskBadge level={d.risk_level} />
                        </td>
                        <td className="px-4 py-3 text-right">
                          {d.replicas ?? "—"}
                        </td>
                      </tr>
                      {expanded[i] && d.deductions?.length > 0 && (
                        <tr key={`${i}-ded`}>
                          <td colSpan={5} className="px-6 py-4 bg-gray-50">
                            <p className="font-semibold text-xs text-gray-600 mb-2">
                              Deductions ({d.deductions.length})
                            </p>
                            <div className="space-y-1.5">
                              {d.deductions.map((dd, j) => (
                                <div
                                  key={j}
                                  className="flex items-start gap-3 text-xs"
                                >
                                  <span className="font-mono text-red-500 w-8 shrink-0 text-right">
                                    {dd.weight}
                                  </span>
                                  <span
                                    className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                                      dd.category === "security"
                                        ? "bg-red-50 text-red-600"
                                        : dd.category === "reliability"
                                        ? "bg-amber-50 text-amber-600"
                                        : "bg-blue-50 text-blue-600"
                                    }`}
                                  >
                                    {dd.category}
                                  </span>
                                  <span className="text-gray-600">
                                    {dd.detail}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
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
