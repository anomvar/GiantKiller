const BASE = "/api/v1";

export function uploadFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${BASE}/upload`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText));
      } else {
        let msg = `Upload failed (${xhr.status})`;
        try {
          msg = JSON.parse(xhr.responseText).detail || msg;
        } catch (_) {}
        reject(new Error(msg));
      }
    };
    xhr.onerror = () => reject(new Error("Network error during upload"));
    const fd = new FormData();
    fd.append("file", file);
    xhr.send(fd);
  });
}

export async function triggerScan(scanId) {
  const r = await fetch(`${BASE}/scan/${scanId}`, { method: "POST" });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `Trigger scan failed (${r.status})`);
  return body;
}

export async function getStatus(scanId) {
  const r = await fetch(`${BASE}/scan/${scanId}/status`);
  if (!r.ok) throw new Error("Status unavailable");
  return r.json();
}

export async function getReport(scanId) {
  const r = await fetch(`${BASE}/scan/${scanId}/report`);
  if (!r.ok) throw new Error("Report unavailable");
  return r.json();
}

export async function getAutopsy(scanId) {
  const r = await fetch(`${BASE}/scan/${scanId}/autopsy`);
  if (!r.ok) throw new Error("Autopsy unavailable");
  return r.json();
}

export async function getGridImpact(scanId) {
  const r = await fetch(`${BASE}/scan/${scanId}/grid-impact`);
  if (!r.ok) throw new Error("Grid impact unavailable");
  return r.json();
}
