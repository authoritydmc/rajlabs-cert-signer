// Base-path aware API client. Works at domain root and under Coolify
// sub-paths (/cert-signer): server injects window.__PKI_BASE_PATH__,
// otherwise we probe the first path segment.
function detectBase() {
  const injected = (window.__PKI_BASE_PATH__ || "").replace(/\/$/, "");
  if (injected) return injected;
  const m = window.location.pathname.match(/^\/([^/]+)(\/.*)?$/);
  if (m && !/^(api|acme|certs|crl|health|docs|redoc)$/.test(m[1])) return "/" + m[1];
  return "";
}

export let API_BASE = detectBase();
export const api = (p) => `${API_BASE}${p}`;
export const setApiBase = (b) => {
  API_BASE = (b || "").replace(/\/$/, "");
};

export const token = () => localStorage.getItem("pki_token") || "";
export const authHeaders = (json = true) => {
  const h = { Authorization: `Bearer ${token()}` };
  if (json) h["Content-Type"] = "application/json";
  return h;
};

export async function apiFetch(path, opts = {}) {
  const res = await fetch(api(path), opts);
  // One-time sub-path probe, GET only: retrying non-idempotent methods could
  // execute them twice against two different backends.
  if (res.status === 404 && !window.__PKI_BASE_PATH__ && (!opts.method || opts.method === "GET")) {
    const seg = window.location.pathname.split("/")[1];
    if (seg) {
      const alt = `/${seg}${path}`;
      if (alt !== api(path)) {
        const r2 = await fetch(alt, opts);
        if (r2.ok || r2.status !== 404) {
          API_BASE = `/${seg}`;
          return r2;
        }
      }
    }
  }
  return res;
}

export async function apiJson(path, opts = {}) {
  const res = await apiFetch(path, opts);
  const data = await res.json().catch(() => ({}));
  return { res, data };
}

export function errText(d, fallback = "Request failed") {
  if (!d || typeof d === "string") return d || fallback;
  let s = d.error || d.message || d.detail || fallback;
  if (d.code) s = `[${d.code}] ${s}`;
  if (d.hint) s += ` — ${d.hint}`;
  return s;
}

export function downloadBlob(filename, text, mime = "application/x-pem-file") {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}
