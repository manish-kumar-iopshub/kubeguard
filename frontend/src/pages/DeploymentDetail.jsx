import { useEffect, useState, useCallback } from "react";
import { Link, useParams } from "react-router-dom";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import {
  getDeploymentDetail,
  postIgnoreRule,
  deleteIgnoreRule,
} from "../api";

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

export default function DeploymentDetail() {
  const { namespace, deployment } = useParams();
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState(null);
  const [busyRule, setBusyRule] = useState(null);

  const load = useCallback(() => {
    setError(null);
    getDeploymentDetail(namespace, deployment)
      .then((d) => {
        if (!d || d.error) setError(d?.error || "Not found");
        else setDetail(d);
      })
      .catch((e) => setError(e.message));
  }, [namespace, deployment]);

  useEffect(() => {
    load();
  }, [load]);

  const ignore = async (rule) => {
    setBusyRule(rule);
    try {
      await postIgnoreRule(namespace, deployment, rule);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyRule(null);
    }
  };

  const unignore = async (rule) => {
    setBusyRule(rule);
    try {
      await deleteIgnoreRule(namespace, deployment, rule);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyRule(null);
    }
  };

  const chartData =
    detail?.history?.map((h) => ({
      ...h,
      label: new Date(h.created_at).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
    })) ?? [];

  const w = detail?.workload;

  return (
    <div>
      <Link
        to="/deployment-risk"
        className="text-sm text-indigo-600 hover:underline mb-4 inline-block"
      >
        ← Back to deployment risk
      </Link>

      <h2 className="text-2xl font-bold mt-2">
        {deployment}
        <span className="text-gray-400 font-normal text-lg">
          {" "}
          · {namespace}
        </span>
      </h2>

      {error && (
        <div className="mt-4 p-3 bg-red-50 text-red-700 rounded-lg text-sm">
          {error}
        </div>
      )}

      {w && (
        <>
          <div className="mt-4 flex flex-wrap gap-6 items-center">
            <div>
              <p className="text-xs text-gray-500 uppercase">Effective score</p>
              <p className="text-3xl font-bold text-indigo-600">
                {w.effective_score}
                <span className="text-base font-normal text-gray-400">
                  /100
                </span>
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase">Raw score</p>
              <p className="text-2xl font-semibold text-gray-700">
                {w.raw_score}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase">Risk (effective)</p>
              <RiskBadge level={w.risk_level} />
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase">Replicas</p>
              <p className="text-lg font-medium">{w.replicas ?? "—"}</p>
            </div>
          </div>

          {detail.latest_scan_at && (
            <p className="text-xs text-gray-400 mt-2">
              Latest scan: {new Date(detail.latest_scan_at).toLocaleString()}
            </p>
          )}

          <h3 className="text-lg font-semibold mt-8 mb-3">Score trend</h3>
          <p className="text-sm text-gray-500 mb-2">
            Raw score is what the scanner reported each run. Effective score
            applies your current ignored rules to historical deductions so you
            can compare “what the score would be” with the same policy across
            runs.
          </p>
          {chartData.length > 0 ? (
            <div className="h-72 w-full bg-white rounded-xl border border-gray-200 p-4">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="label" tick={{ fontSize: 10 }} />
                  <YAxis domain={[0, 100]} />
                  <Tooltip />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="raw_score"
                    name="Raw score"
                    stroke="#94a3b8"
                    strokeWidth={2}
                    dot
                  />
                  <Line
                    type="monotone"
                    dataKey="effective_score"
                    name="Effective (current ignores)"
                    stroke="#4f46e5"
                    strokeWidth={2}
                    dot
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-sm text-gray-400">
              Run more deployment scans to see a trend (need at least one
              historical point with this workload).
            </p>
          )}

          <h3 className="text-lg font-semibold mt-8 mb-3">Rule changes vs previous scan</h3>
          <div className="bg-white rounded-xl border border-gray-200 divide-y max-h-48 overflow-y-auto text-sm">
            {detail.history?.length ? (
              [...detail.history].reverse().slice(0, 12).map((h, i) => (
                <div key={h.scan_id} className="px-4 py-2">
                  <p className="text-xs text-gray-400">
                    {new Date(h.created_at).toLocaleString()}
                  </p>
                  {h.rules_added_vs_previous?.length > 0 && (
                    <p className="text-amber-700">
                      + New: {h.rules_added_vs_previous.join(", ")}
                    </p>
                  )}
                  {h.rules_removed_vs_previous?.length > 0 && (
                    <p className="text-green-700">
                      − Resolved: {h.rules_removed_vs_previous.join(", ")}
                    </p>
                  )}
                  {i === 0 &&
                    !h.rules_added_vs_previous?.length &&
                    !h.rules_removed_vs_previous?.length && (
                      <p className="text-gray-400">No change vs previous</p>
                    )}
                </div>
              ))
            ) : (
              <p className="p-4 text-gray-400">No history</p>
            )}
          </div>

          <h3 className="text-lg font-semibold mt-8 mb-3">Findings & ignore policy</h3>
          <p className="text-sm text-gray-500 mb-3">
            Ignoring a rule adds points back to the effective score (stored in
            MongoDB). It does not change past raw scan payloads.
          </p>
          <div className="space-y-2">
            {(w.deductions || []).map((d, idx) => (
              <div
                key={`${d.rule}-${idx}`}
                className={`flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg border ${
                  d.ignored
                    ? "bg-gray-100 border-gray-200 opacity-80"
                    : "bg-white border-gray-200"
                }`}
              >
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-mono text-red-600">{d.weight}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                      d.category === "security"
                        ? "bg-red-50 text-red-600"
                        : d.category === "reliability"
                        ? "bg-amber-50 text-amber-600"
                        : "bg-blue-50 text-blue-600"
                    }`}
                  >
                    {d.category}
                  </span>
                  <span className="font-mono text-xs text-gray-500">
                    {d.rule}
                  </span>
                  <span className="text-gray-600">{d.detail}</span>
                  {d.ignored && (
                    <span className="text-xs text-gray-500">(ignored)</span>
                  )}
                </div>
                <div>
                  {d.ignored ? (
                    <button
                      type="button"
                      disabled={busyRule === d.rule}
                      onClick={() => unignore(d.rule)}
                      className="text-sm text-indigo-600 hover:underline disabled:opacity-50"
                    >
                      Stop ignoring
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={busyRule === d.rule}
                      onClick={() => ignore(d.rule)}
                      className="text-sm px-3 py-1 rounded-lg bg-gray-800 text-white hover:bg-gray-700 disabled:opacity-50"
                    >
                      Ignore risk
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
