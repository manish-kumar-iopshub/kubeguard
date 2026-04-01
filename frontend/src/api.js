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
