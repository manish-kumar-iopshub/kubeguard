import { useEffect, useState } from "react";
import { getDashboard, getScans } from "../api";

const SCAN_LABELS = {
  pods: "Unhealthy Pods",
  secrets: "Secret Leakage",
  deployments: "Deployment Risk",
};

function StatCard({ title, children, color }) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">
      <h3 className="text-sm font-medium text-gray-500 mb-3">{title}</h3>
      <div className={color}>{children}</div>
    </div>
  );
}

function StatusBadge({ status }) {
  const cls = {
    completed: "bg-green-100 text-green-700",
    running: "bg-blue-100 text-blue-700 animate-pulse",
    failed: "bg-red-100 text-red-700",
  }[status] || "bg-gray-100 text-gray-600";
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

export default function Dashboard() {
  const [dashboard, setDashboard] = useState(null);
  const [scans, setScans] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    Promise.all([getDashboard(), getScans()])
      .then(([d, s]) => {
        setDashboard(d);
        setScans(s || []);
      })
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="text-center py-20 text-red-600">
        <p className="text-lg font-semibold">Failed to load dashboard</p>
        <p className="text-sm mt-1">{error}</p>
      </div>
    );
  }

  if (!dashboard) {
    return <div className="text-center py-20 text-gray-400">Loading…</div>;
  }

  const latest = dashboard.latest || {};

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-8">
        <StatCard title="Unhealthy Pods" color="text-red-600">
          {latest.pods ? (
            <>
              <p className="text-3xl font-bold">
                {latest.pods.summary?.unhealthy_count ?? "—"}
              </p>
              <p className="text-xs text-gray-400 mt-1">
                of {latest.pods.summary?.total_scanned ?? "?"} scanned
              </p>
            </>
          ) : (
            <p className="text-sm text-gray-400">No scan yet</p>
          )}
        </StatCard>

        <StatCard title="Secret Findings" color="text-amber-600">
          {latest.secrets ? (
            <>
              <p className="text-3xl font-bold">
                {latest.secrets.summary?.total_findings ?? "—"}
              </p>
              <p className="text-xs text-gray-400 mt-1">
                H:{latest.secrets.summary?.high ?? 0} M:
                {latest.secrets.summary?.medium ?? 0} L:
                {latest.secrets.summary?.low ?? 0}
              </p>
            </>
          ) : (
            <p className="text-sm text-gray-400">No scan yet</p>
          )}
        </StatCard>

        <StatCard title="Avg Deployment Score" color="text-indigo-600">
          {latest.deployments ? (
            <>
              <p className="text-3xl font-bold">
                {latest.deployments.summary?.average_score ?? "—"}
                <span className="text-base font-normal text-gray-400">
                  /100
                </span>
              </p>
              <p className="text-xs text-gray-400 mt-1">
                {latest.deployments.summary?.total_scored ?? 0} deployments
                scored
              </p>
            </>
          ) : (
            <p className="text-sm text-gray-400">No scan yet</p>
          )}
        </StatCard>
      </div>

      <h3 className="text-lg font-semibold mb-3">Recent Scans</h3>
      {scans.length === 0 ? (
        <p className="text-sm text-gray-400">
          No scans yet. Go to a scanner page and run one.
        </p>
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
              <tr>
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Started</th>
                <th className="px-4 py-3 text-left">Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {scans.slice(0, 20).map((s) => (
                <tr key={s._id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium">
                    {SCAN_LABELS[s.scan_type] || s.scan_type}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={s.status} />
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {s.created_at
                      ? new Date(s.created_at).toLocaleString()
                      : "—"}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    {s.summary
                      ? JSON.stringify(s.summary)
                          .replace(/[{}"]/g, "")
                          .replace(/,/g, " · ")
                      : s.error || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
