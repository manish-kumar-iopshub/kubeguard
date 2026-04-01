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
