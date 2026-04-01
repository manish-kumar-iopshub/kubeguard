import { useEffect, useState, useCallback } from "react";
import { getLatestScan, triggerScan, pollScan } from "../api";

function ReasonBadge({ reason }) {
  const colors = {
    CrashLoopBackOff: "bg-red-100 text-red-700",
    OOMKilled: "bg-red-100 text-red-800",
    ImagePullBackOff: "bg-amber-100 text-amber-700",
    ErrImagePull: "bg-amber-100 text-amber-700",
    CreateContainerError: "bg-orange-100 text-orange-700",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded-full text-xs font-medium ${
        colors[reason] || "bg-gray-100 text-gray-600"
      }`}
    >
      {reason}
    </span>
  );
}

export default function UnhealthyPods() {
  const [scan, setScan] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    getLatestScan("pods")
      .then(setScan)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(load, [load]);

  const runScan = async () => {
    setScanning(true);
    setError(null);
    try {
      const { scan_id } = await triggerScan("pods");
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

  const pods = scan?.data?.unhealthy_pods || [];

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold">Unhealthy Pods</h2>
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

      {pods.length === 0 && scan && (
        <div className="text-center py-16 text-green-600">
          <p className="text-3xl mb-2">✓</p>
          <p className="font-semibold">All pods healthy</p>
          <p className="text-sm text-gray-400 mt-1">
            {scan.data?.total_pods_scanned ?? 0} pods scanned
          </p>
        </div>
      )}

      {pods.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
              <tr>
                <th className="px-4 py-3 text-left">Pod</th>
                <th className="px-4 py-3 text-left">Namespace</th>
                <th className="px-4 py-3 text-left">Reason</th>
                <th className="px-4 py-3 text-left">Node</th>
                <th className="px-4 py-3 text-right">Restarts</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {pods.map((p, i) => (
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
                      {p.pod_name}
                    </td>
                    <td className="px-4 py-3 text-gray-500">{p.namespace}</td>
                    <td className="px-4 py-3">
                      <ReasonBadge reason={p.reason} />
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {p.node_name || "—"}
                    </td>
                    <td className="px-4 py-3 text-right">{p.restart_count}</td>
                  </tr>
                  {expanded[i] && p.diagnostics && (
                    <tr key={`${i}-diag`}>
                      <td colSpan={5} className="px-6 py-4 bg-gray-50">
                        <div className="space-y-3 text-xs">
                          {p.diagnostics.owner && (
                            <div>
                              <span className="font-semibold text-gray-600">
                                Owner:{" "}
                              </span>
                              {p.diagnostics.owner}
                            </div>
                          )}
                          {p.diagnostics.images?.length > 0 && (
                            <div>
                              <span className="font-semibold text-gray-600">
                                Images:{" "}
                              </span>
                              {p.diagnostics.images.join(", ")}
                            </div>
                          )}
                          {p.diagnostics.warning_events?.length > 0 && (
                            <div>
                              <p className="font-semibold text-gray-600 mb-1">
                                Warning Events:
                              </p>
                              <ul className="list-disc list-inside text-gray-500 space-y-0.5">
                                {p.diagnostics.warning_events.map((e, j) => (
                                  <li key={j}>{e}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                          {p.diagnostics.last_logs && (
                            <div>
                              <p className="font-semibold text-gray-600 mb-1">
                                Last Logs:
                              </p>
                              <pre className="bg-gray-800 text-green-300 p-3 rounded-lg overflow-x-auto max-h-40 whitespace-pre-wrap">
                                {p.diagnostics.last_logs}
                              </pre>
                            </div>
                          )}
                          {p.diagnostics.previous_logs && (
                            <div>
                              <p className="font-semibold text-gray-600 mb-1">
                                Previous Logs:
                              </p>
                              <pre className="bg-gray-800 text-amber-300 p-3 rounded-lg overflow-x-auto max-h-40 whitespace-pre-wrap">
                                {p.diagnostics.previous_logs}
                              </pre>
                            </div>
                          )}
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
    </div>
  );
}
