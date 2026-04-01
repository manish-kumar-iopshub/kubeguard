import { useEffect, useState, useCallback } from "react";
import { getLatestScan, triggerScan, pollScan } from "../api";

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

export default function SecretLeakage() {
  const [scan, setScan] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    getLatestScan("secrets")
      .then(setScan)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(load, [load]);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { scan_id } = await triggerScan("secrets");
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

  const findings = scan?.data?.findings || [];
  const severity = scan?.data?.summary_by_severity || {};

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold">Secret Leakage Scanner</h2>
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
          {scanning ? "Scanning…" : "Run Scan"}
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

          {findings.length === 0 ? (
            <div className="text-center py-16 text-green-600">
              <p className="text-3xl mb-2">✓</p>
              <p className="font-semibold">No secret leakage detected</p>
            </div>
          ) : (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
                  <tr>
                    <th className="px-4 py-3 text-left">Severity</th>
                    <th className="px-4 py-3 text-left">Kind</th>
                    <th className="px-4 py-3 text-left">Namespace / Object</th>
                    <th className="px-4 py-3 text-left">Rule</th>
                    <th className="px-4 py-3 text-left">Message</th>
                    <th className="px-4 py-3 text-left">Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {findings.map((f, i) => (
                    <tr key={i} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-4 py-3 font-medium">{f.kind}</td>
                      <td className="px-4 py-3 text-gray-500">
                        <span className="text-gray-400">{f.namespace}/</span>
                        {f.object_name}
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-gray-500">
                        {f.rule_id}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-600 max-w-xs truncate">
                        {f.message}
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-gray-400">
                        {f.evidence_masked || "—"}
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
