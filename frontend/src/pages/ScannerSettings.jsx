import { useEffect, useState, useCallback } from "react";
import { getScannerSettings, saveScannerSettings } from "../api";

function parseList(text) {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export default function ScannerSettings() {
  const [excludeNs, setExcludeNs] = useState("");
  const [skipWl, setSkipWl] = useState("");
  const [saved, setSaved] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    getScannerSettings()
      .then((s) => {
        setExcludeNs((s?.exclude_namespaces || []).join("\n"));
        setSkipWl((s?.skip_workloads || []).join("\n"));
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const save = async () => {
    setSaved(null);
    setError(null);
    try {
      const body = await saveScannerSettings({
        exclude_namespaces: parseList(excludeNs),
        skip_workloads: parseList(skipWl),
      });
      setExcludeNs((body.exclude_namespaces || []).join("\n"));
      setSkipWl((body.skip_workloads || []).join("\n"));
      setSaved("Saved to MongoDB. Next deployment scan will merge these with any one-off API params.");
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="max-w-2xl">
      <h2 className="text-2xl font-bold mb-2">Scanner settings</h2>
      <p className="text-sm text-gray-600 mb-6">
        Namespaces and workload names listed here are merged into every{" "}
        <strong>deployment risk</strong> scan (and can still be extended per
        request). Values are stored in MongoDB.
      </p>

      {loading && <p className="text-gray-400">Loading…</p>}
      {error && (
        <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg text-sm">
          {error}
        </div>
      )}
      {saved && (
        <div className="mb-4 p-3 bg-green-50 text-green-800 rounded-lg text-sm">
          {saved}
        </div>
      )}

      {!loading && (
        <>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Exclude namespaces (one per line or comma-separated)
          </label>
          <textarea
            value={excludeNs}
            onChange={(e) => setExcludeNs(e.target.value)}
            rows={5}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono mb-4"
            placeholder="kube-system&#10;monitoring"
          />

          <label className="block text-sm font-medium text-gray-700 mb-1">
            Skip workloads (name only, or namespace/name)
          </label>
          <textarea
            value={skipWl}
            onChange={(e) => setSkipWl(e.target.value)}
            rows={5}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono mb-4"
            placeholder="coredns&#10;argocd/argocd-server"
          />

          <button
            type="button"
            onClick={save}
            className="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700"
          >
            Save settings
          </button>
        </>
      )}
    </div>
  );
}
