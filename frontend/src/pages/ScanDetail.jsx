import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getScan } from "../api";

const SCAN_LABELS = {
  pods: "Unhealthy Pods",
  secrets: "Secret Leakage",
  deployments: "Deployment Risk",
  api_pt: "API Pen Test",
};

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

export default function ScanDetail() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scanId) return;
    setError(null);
    getScan(scanId)
      .then((doc) => {
        if (!doc) setError("Scan not found.");
        else setScan(doc);
      })
      .catch((e) => setError(e.message));
  }, [scanId]);

  if (error) {
    return (
      <div>
        <Link
          to="/"
          className="text-sm text-indigo-600 hover:underline mb-4 inline-block"
        >
          ← Back to dashboard
        </Link>
        <div className="p-4 bg-red-50 text-red-700 rounded-lg text-sm">{error}</div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-20 text-gray-400">Loading scan…</div>
    );
  }

  const label = SCAN_LABELS[scan.scan_type] || scan.scan_type;
  const { data, summary, meta, ...rest } = scan;

  return (
    <div>
      <Link
        to="/"
        className="text-sm text-indigo-600 hover:underline mb-4 inline-block"
      >
        ← Back to dashboard
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <h2 className="text-2xl font-bold">Scan detail</h2>
          <p className="text-sm text-gray-500 mt-1">
            <span className="font-medium text-gray-800">{label}</span>
            <span className="text-gray-400 mx-2">·</span>
            <code className="text-xs bg-gray-100 px-1.5 py-0.5 rounded">
              {scan._id}
            </code>
          </p>
        </div>
        <StatusBadge status={scan.status} />
      </div>

      <div className="space-y-6">
        <section className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-gray-800 mb-3">Metadata</h3>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            <div>
              <dt className="text-gray-500">Created</dt>
              <dd className="font-mono text-xs mt-0.5">
                {scan.created_at
                  ? new Date(scan.created_at).toLocaleString()
                  : "—"}
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">Completed</dt>
              <dd className="font-mono text-xs mt-0.5">
                {scan.completed_at
                  ? new Date(scan.completed_at).toLocaleString()
                  : "—"}
              </dd>
            </div>
            {scan.error && (
              <div className="sm:col-span-2">
                <dt className="text-gray-500">Error</dt>
                <dd className="mt-1 text-red-700 text-sm whitespace-pre-wrap">
                  {scan.error}
                </dd>
              </div>
            )}
            {summary != null && Object.keys(summary).length > 0 && (
              <div className="sm:col-span-2">
                <dt className="text-gray-500 mb-1">Summary</dt>
                <dd>
                  <pre className="text-xs bg-gray-50 border border-gray-100 rounded-lg p-3 overflow-x-auto">
                    {JSON.stringify(summary, null, 2)}
                  </pre>
                </dd>
              </div>
            )}
            {meta != null && Object.keys(meta).length > 0 && (
              <div className="sm:col-span-2">
                <dt className="text-gray-500 mb-1">Meta</dt>
                <dd>
                  <pre className="text-xs bg-gray-50 border border-gray-100 rounded-lg p-3 overflow-x-auto">
                    {JSON.stringify(meta, null, 2)}
                  </pre>
                </dd>
              </div>
            )}
          </dl>
        </section>

        <section className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 bg-gray-50">
            <h3 className="text-sm font-semibold text-gray-800">Full payload</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Raw document fields (excluding duplicated large{" "}
              <code className="bg-gray-200 px-1 rounded">data</code> below).
            </p>
          </div>
          <pre className="text-xs p-4 overflow-x-auto max-h-64 bg-white">
            {JSON.stringify(rest, null, 2)}
          </pre>
        </section>

        <section className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 bg-gray-50">
            <h3 className="text-sm font-semibold text-gray-800">Data</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Complete scan result body returned by the scanner.
            </p>
          </div>
          {data == null ? (
            <p className="p-4 text-sm text-gray-400">No data (running or failed).</p>
          ) : (
            <pre className="text-xs p-4 overflow-auto max-h-[70vh] bg-slate-900 text-slate-100 font-mono leading-relaxed">
              {JSON.stringify(data, null, 2)}
            </pre>
          )}
        </section>
      </div>
    </div>
  );
}
