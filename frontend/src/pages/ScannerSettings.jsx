import { useEffect, useState, useCallback } from "react";
import {
  getScannerSettings,
  saveScannerSettings,
  getSecretScannerSettings,
  saveSecretScannerSettings,
} from "../api";

function parseList(text) {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export default function ScannerSettings() {
  const [depExcludeNs, setDepExcludeNs] = useState("");
  const [depSkipWl, setDepSkipWl] = useState("");
  const [secExcludeNs, setSecExcludeNs] = useState("");
  const [secExcludeRes, setSecExcludeRes] = useState("");
  const [savedDep, setSavedDep] = useState(null);
  const [savedSec, setSavedSec] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([getScannerSettings(), getSecretScannerSettings()])
      .then(([d, s]) => {
        setDepExcludeNs((d?.exclude_namespaces || []).join("\n"));
        setDepSkipWl((d?.skip_workloads || []).join("\n"));
        setSecExcludeNs((s?.exclude_namespaces || []).join("\n"));
        setSecExcludeRes((s?.exclude_resources || []).join("\n"));
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const saveDeployment = async () => {
    setSavedDep(null);
    setError(null);
    try {
      const body = await saveScannerSettings({
        exclude_namespaces: parseList(depExcludeNs),
        skip_workloads: parseList(depSkipWl),
      });
      setDepExcludeNs((body.exclude_namespaces || []).join("\n"));
      setDepSkipWl((body.skip_workloads || []).join("\n"));
      setSavedDep(
        "Deployment risk settings saved. They apply only to deployment scoring scans."
      );
    } catch (e) {
      setError(e.message);
    }
  };

  const saveSecret = async () => {
    setSavedSec(null);
    setError(null);
    try {
      const body = await saveSecretScannerSettings({
        exclude_namespaces: parseList(secExcludeNs),
        exclude_resources: parseList(secExcludeRes),
      });
      setSecExcludeNs((body.exclude_namespaces || []).join("\n"));
      setSecExcludeRes((body.exclude_resources || []).join("\n"));
      setSavedSec(
        "Secret / ConfigMap scanner settings saved. Next leakage scan merges these exclusions."
      );
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="max-w-3xl space-y-10">
      <h2 className="text-2xl font-bold">Scanner settings</h2>
      <p className="text-sm text-gray-600 -mt-6">
        Deployment risk and secret leakage use <strong>separate</strong> exclusion
        lists in MongoDB so you can tune each workflow independently.
      </p>

      {loading && <p className="text-gray-400">Loading…</p>}
      {error && (
        <div className="p-3 bg-red-50 text-red-700 rounded-lg text-sm">{error}</div>
      )}

      {!loading && (
        <>
          <section className="border border-gray-200 rounded-xl p-6 bg-white shadow-sm">
            <h3 className="text-lg font-semibold text-gray-900 mb-1">
              Deployment risk scorer
            </h3>
            <p className="text-sm text-gray-600 mb-4">
              Namespaces are skipped entirely. Workloads are skipped by name only
              or <code className="text-xs bg-gray-100 px-1 rounded">namespace/name</code>.
            </p>
            {savedDep && (
              <div className="mb-4 p-3 bg-green-50 text-green-800 rounded-lg text-sm">
                {savedDep}
              </div>
            )}
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Exclude namespaces
            </label>
            <textarea
              value={depExcludeNs}
              onChange={(e) => setDepExcludeNs(e.target.value)}
              rows={4}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono mb-4"
              placeholder="kube-system"
            />
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Skip workloads
            </label>
            <textarea
              value={depSkipWl}
              onChange={(e) => setDepSkipWl(e.target.value)}
              rows={4}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono mb-4"
              placeholder="coredns&#10;argocd/argocd-server"
            />
            <button
              type="button"
              onClick={saveDeployment}
              className="px-4 py-2 bg-slate-800 text-white text-sm font-medium rounded-lg hover:bg-slate-900"
            >
              Save deployment risk settings
            </button>
          </section>

          <section className="border border-amber-200 rounded-xl p-6 bg-amber-50/30 shadow-sm">
            <h3 className="text-lg font-semibold text-gray-900 mb-1">
              Secret / ConfigMap leakage scanner
            </h3>
            <p className="text-sm text-gray-600 mb-4">
              <strong>Exclude namespaces:</strong> skip all ConfigMaps and Secrets in
              those namespaces.
              <br />
              <strong>Exclude resources:</strong> one per line. Use{" "}
              <code className="text-xs bg-white px-1 rounded border">
                configmap:ns/name
              </code>{" "}
              or{" "}
              <code className="text-xs bg-white px-1 rounded border">
                secret:ns/name
              </code>
              . Short aliases: <code className="text-xs">cm:</code>,{" "}
              <code className="text-xs">sec:</code>. A bare{" "}
              <code className="text-xs">ns/name</code> skips both a ConfigMap and a
              Secret with that name in that namespace.
            </p>
            {savedSec && (
              <div className="mb-4 p-3 bg-green-50 text-green-800 rounded-lg text-sm">
                {savedSec}
              </div>
            )}
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Exclude namespaces
            </label>
            <textarea
              value={secExcludeNs}
              onChange={(e) => setSecExcludeNs(e.target.value)}
              rows={4}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono mb-4 bg-white"
              placeholder="kube-system"
            />
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Exclude specific ConfigMaps / Secrets
            </label>
            <textarea
              value={secExcludeRes}
              onChange={(e) => setSecExcludeRes(e.target.value)}
              rows={6}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono mb-4 bg-white"
              placeholder={
                "configmap:prod/app-config\nsecret:prod/db-credentials\nstaging/shared-config"
              }
            />
            <button
              type="button"
              onClick={saveSecret}
              className="px-4 py-2 bg-amber-600 text-white text-sm font-medium rounded-lg hover:bg-amber-700"
            >
              Save secret scanner settings
            </button>
          </section>
        </>
      )}
    </div>
  );
}
