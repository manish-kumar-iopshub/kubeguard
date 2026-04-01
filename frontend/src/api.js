const API = "/api";

async function request(url, options = {}) {
  const res = await fetch(`${API}${url}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok && res.status !== 404) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Request failed: ${res.status}`);
  }
  if (res.status === 404) return null;
  return res.json();
}

export const getDashboard = () => request("/dashboard/");

export const getScans = () => request("/scans/");

export const getScan = (id) => request(`/scans/${id}/`);

export const getLatestScan = (type) => request(`/scans/${type}/latest/`);

export const triggerScan = (type, params = {}) =>
  request(`/scans/${type}/trigger/`, {
    method: "POST",
    body: JSON.stringify(params),
  });

export const getScannerSettings = () => request("/settings/scanner/");

export const saveScannerSettings = (body) =>
  request("/settings/scanner/", { method: "PUT", body: JSON.stringify(body) });

export const getSecretScannerSettings = () =>
  request("/settings/secret-scanner/");

export const saveSecretScannerSettings = (body) =>
  request("/settings/secret-scanner/", { method: "PUT", body: JSON.stringify(body) });

export const getPodAlertSettings = () => request("/settings/pod-alerts/");

export const savePodAlertSettings = (body) =>
  request("/settings/pod-alerts/", { method: "PUT", body: JSON.stringify(body) });

function secretPath(namespace, kind, objectName) {
  return `/secrets/${encodeURIComponent(namespace)}/${encodeURIComponent(
    kind
  )}/${encodeURIComponent(objectName)}/`;
}

export const ignoreSecretIssue = (namespace, kind, objectName, issueId) =>
  request(`${secretPath(namespace, kind, objectName)}ignore-issue/`, {
    method: "POST",
    body: JSON.stringify({ issue_id: issueId }),
  });

export const unignoreSecretIssue = (namespace, kind, objectName, issueId) =>
  request(
    `${secretPath(
      namespace,
      kind,
      objectName
    )}ignore-issue/?issue_id=${encodeURIComponent(issueId)}`,
    { method: "DELETE" }
  );

export const ignoreSecretResource = (namespace, kind, objectName) =>
  request(`${secretPath(namespace, kind, objectName)}ignore-resource/`, {
    method: "POST",
  });

export const unignoreSecretResource = (namespace, kind, objectName) =>
  request(`${secretPath(namespace, kind, objectName)}ignore-resource/`, {
    method: "DELETE",
  });

/** Combined list of whole-resource excludes and per-leak ignores (for restore UI). */
export const getSecretLeakIgnores = () => request("/secret-leakage/ignores/");

export function deploymentPath(namespace, deployment) {
  const ns = encodeURIComponent(namespace);
  const dep = encodeURIComponent(deployment);
  return `/deployments/${ns}/${dep}/`;
}

export const getDeploymentDetail = (namespace, deployment) =>
  request(deploymentPath(namespace, deployment));

export const postIgnoreRule = (namespace, deployment, rule) =>
  request(`${deploymentPath(namespace, deployment)}ignore-rule/`, {
    method: "POST",
    body: JSON.stringify({ rule }),
  });

export const deleteIgnoreRule = (namespace, deployment, rule) =>
  request(
    `${deploymentPath(namespace, deployment)}ignore-rule/?rule=${encodeURIComponent(rule)}`,
    { method: "DELETE" }
  );

export function pollScan(scanId, onUpdate, interval = 2000) {
  let stopped = false;
  const poll = async () => {
    if (stopped) return;
    try {
      const data = await getScan(scanId);
      onUpdate(data);
      if (data && data.status === "running") {
        setTimeout(poll, interval);
      }
    } catch {
      setTimeout(poll, interval * 2);
    }
  };
  poll();
  return () => {
    stopped = true;
  };
}
