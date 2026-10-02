import { useEffect, useState } from "react";
import { apiFetch, apiJson, authHeaders, downloadBlob, errText, token } from "../api";
import { Btn, Card, Empty, Modal, inp, useToast } from "../ui";

function expiryBadge(c) {
  if (c.status === "revoked") return <span className="text-slate-500 text-[11px]">n/a (revoked)</span>;
  if (c.status === "renewed") return <span className="text-slate-500 text-[11px]">superseded</span>;
  if (c.daysRemaining == null) return <span className="text-slate-500 text-[11px]">unknown</span>;
  if (c.daysRemaining < 0) return <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-300">expired</span>;
  if (c.daysRemaining <= 7) return <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-300">{c.daysRemaining}d left</span>;
  if (c.daysRemaining <= 30) return <span className="rounded bg-amber-500/15 px-2 py-0.5 text-xs text-amber-300">{c.daysRemaining}d left</span>;
  return <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">{c.daysRemaining}d left</span>;
}

function StatusBadge({ c }) {
  if (c.expired) return <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-300">expired</span>;
  if (c.status === "valid") return <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">valid</span>;
  if (c.status === "revoked") return <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-300">revoked</span>;
  return <span className="rounded bg-slate-500/15 px-2 py-0.5 text-xs text-slate-300">{c.status}</span>;
}

export default function Certs({ onChanged }) {
  const toast = useToast();
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [cas, setCas] = useState([]);
  const [issuers, setIssuers] = useState([]);
  const [f, setF] = useState({ q: "", status: "", ca: "", exp: "", via: "" });
  const [sel, setSel] = useState(new Set());
  const [detail, setDetail] = useState(null);

  async function load() {
    const params = new URLSearchParams({ limit: "200", offset: "0" });
    if (f.status) params.set("status", f.status);
    if (f.ca) params.set("ca", f.ca);
    if (f.exp) params.set("expiringDays", f.exp);
    if (f.q.trim()) params.set("q", f.q.trim());
    const { data } = await apiJson("/api/admin/certificates?" + params.toString(), { headers: authHeaders() });
    const entries = Array.isArray(data) ? data : data.entries || [];
    setRows(entries);
    setTotal(Array.isArray(data) ? entries.length : data.total);
    if (data.filterOptions) {
      setCas(data.filterOptions.cas || []);
      setIssuers(data.filterOptions.issuers || []);
    }
    setSel(new Set());
  }
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [f.status, f.ca, f.exp]);

  const shown = f.via ? rows.filter((c) => (c.issuedViaTokenName || "") === f.via) : rows;
  const toggle = (s) => setSel((prev) => {
    const n = new Set(prev);
    if (n.has(s)) n.delete(s);
    else n.add(s);
    return n;
  });

  async function revoke(serial) {
    const reason = prompt("Revocation reason (keyCompromise, cessationOfOperation, …):", "keyCompromise") || "unspecified";
    let { res, data } = await apiJson(`/api/v1/certificates/${serial}?reason=${encodeURIComponent(reason)}`, {
      method: "DELETE", headers: authHeaders(),
    });
    if (res.status === 404 && data && data.error === "Not found.") {
      // Older server without the DELETE route — fall back to POST revoke.
      ({ data } = await apiJson("/api/v1/revoke", {
        method: "POST", headers: authHeaders(), body: JSON.stringify({ serial, reason }),
      }));
    }
    if (data.success) toast(`Revoked 0x${serial} via ${(data.via || "post").toUpperCase()}. CRL: ${data.crlRegenerated ? "regenerated ✅" : "pending ⚠️"}`);
    else toast(errText(data), true);
    load();
    onChanged();
  }

  async function bulkRevoke() {
    if (!sel.size) return toast("Select certificates first");
    const serials = [...sel];
    const reason = prompt(`Reason for revoking ${serials.length} certificate(s):`, "cessationOfOperation") || "unspecified";
    const { data } = await apiJson("/api/v1/revoke-bulk", {
      method: "POST", headers: authHeaders(), body: JSON.stringify({ serials, reason }),
    });
    if (data.success) toast(`Revoked ${data.revoked}, already ${(data.alreadyRevoked || []).length}, not found ${(data.notFound || []).length}. CRL: ${data.crlRegenerated ? "✅" : "⚠️"}`);
    else toast(errText(data), true);
    load();
    onChanged();
  }

  async function download(serial, kind) {
    const res = await apiFetch(`/api/admin/certificates/${serial}/download?kind=${kind}`, {
      headers: { Authorization: `Bearer ${token()}` },
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      return toast(errText(d, "Download failed"), true);
    }
    downloadBlob(`${serial}-${kind}.pem`, await res.text());
  }

  async function bulkDownload() {
    if (!sel.size) return toast("Select certificates first");
    let bundle = "";
    for (const s of sel) {
      const res = await apiFetch(`/api/admin/certificates/${s}/download?kind=chain`, {
        headers: { Authorization: `Bearer ${token()}` },
      });
      if (res.ok) bundle += `\n# ===== 0x${s} =====\n` + (await res.text());
    }
    if (!bundle) return toast("No chains downloadable (files missing?)", true);
    downloadBlob(`cert-bundle-${sel.size}.pem`, bundle);
    toast(`Bundled ${sel.size} chain(s).`);
  }

  async function renew(serial) {
    const days = prompt("Renew with validity (days):", "90") || "90";
    if (!confirm(`Renew 0x${serial} with a fresh key + serial? The old cert is marked superseded (not CRL-listed).`)) return;
    const { data } = await apiJson(`/api/admin/certificates/${serial}/renew`, {
      method: "POST", headers: authHeaders(), body: JSON.stringify({ days }),
    });
    if (data.success) {
      toast(`Renewed 0x${data.oldSerial} → 0x${data.newSerial}.`);
      downloadBlob(`${data.newSerial}-key.pem`, data.privateKey);
      downloadBlob(`${data.newSerial}-chain.pem`, data.fullChain);
    } else toast(errText(data), true);
    load();
    onChanged();
  }

  async function view(serial) {
    const { data } = await apiJson(`/api/admin/certificates/${serial}`, { headers: authHeaders() });
    if (!data.success) return toast(errText(data), true);
    setDetail(data.certificate);
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div>
          <h1 className="text-2xl font-extrabold">Issued Certificates</h1>
          <p className="text-sm text-slate-400">Full lifecycle: filter, inspect, download, renew, revoke. Showing {shown.length} of {total}.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Btn color="outline" onClick={bulkDownload}>⬇ Bundle Selected</Btn>
          <Btn color="danger" onClick={bulkRevoke}>🚫 Revoke Selected</Btn>
          <Btn color="outline" onClick={load}>↻</Btn>
        </div>
      </div>

      <Card className="mb-4">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          <input value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="🔍 serial, SAN, fingerprint…" className={inp} />
          <select value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })} className={inp}>
            <option value="">All statuses</option>
            <option value="valid">valid</option><option value="revoked">revoked</option>
            <option value="renewed">renewed</option><option value="expired">expired</option>
          </select>
          <select value={f.ca} onChange={(e) => setF({ ...f, ca: e.target.value })} className={inp}>
            <option value="">All CAs</option>{cas.map((c) => <option key={c}>{c}</option>)}
          </select>
          <select value={f.exp} onChange={(e) => setF({ ...f, exp: e.target.value })} className={inp}>
            <option value="">Any expiry</option><option value="7">Expiring ≤ 7d</option>
            <option value="30">Expiring ≤ 30d</option><option value="90">Expiring ≤ 90d</option>
          </select>
          <select value={f.via} onChange={(e) => setF({ ...f, via: e.target.value })} className={inp}>
            <option value="">Any issuer key</option>{issuers.map((v) => <option key={v}>{v}</option>)}
          </select>
        </div>
      </Card>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead><tr className="text-slate-400">
              <th className="p-2"><input type="checkbox" checked={shown.length > 0 && shown.every((c) => sel.has(c.serial))}
                onChange={(e) => setSel(e.target.checked ? new Set(shown.map((c) => c.serial)) : new Set())} /></th>
              <th className="p-2">Serial</th><th className="p-2">Identity</th><th className="p-2">CA</th>
              <th className="p-2">Expires</th><th className="p-2">Via</th><th className="p-2">Status</th><th className="p-2">Actions</th>
            </tr></thead>
            <tbody>
              {shown.map((c) => (
                <tr key={c.serial} className="border-t border-slate-800">
                  <td className="p-2"><input type="checkbox" className="accent-cyan-500" checked={sel.has(c.serial)} onChange={() => toggle(c.serial)} /></td>
                  <td className="p-2 mono text-xs">0x{c.serial}
                    <div className="text-[10px] text-slate-500" title={c.sha256Fingerprint || ""}>
                      {c.sha256Fingerprint ? `Ⓕ ${c.sha256Fingerprint.slice(0, 17)}…` : "no fingerprint"}
                    </div></td>
                  <td className="p-2 text-xs">
                    <div className="font-semibold">{c.commonName || (c.sanDomains || [])[0] || "-"}</div>
                    <div className="text-slate-400">{(c.sanDomains || []).slice(1).join(", ")}</div></td>
                  <td className="p-2 text-xs">{c.caName || "-"}
                    {c.caSelection && <div className="text-[10px] text-slate-500 mono">{c.caSelection}</div>}</td>
                  <td className="p-2 text-xs text-slate-400 whitespace-nowrap">
                    {c.expiresAt ? new Date(c.expiresAt).toLocaleDateString() : "-"}<br />{expiryBadge(c)}</td>
                  <td className="p-2 text-xs text-slate-400">{c.issuedViaTokenName || "—"}
                    <div className="text-[10px] text-slate-600">{c.issuedAt ? new Date(c.issuedAt).toLocaleDateString() : ""}</div></td>
                  <td className="p-2"><StatusBadge c={c} />
                    {c.supersededBy && <div className="text-[10px] text-slate-500 mono">→ 0x{c.supersededBy}</div>}</td>
                  <td className="p-2 whitespace-nowrap text-xs flex flex-wrap gap-1">
                    <button className="rounded border border-slate-600 px-2 py-1" onClick={() => view(c.serial)}>View</button>
                    {c.status === "valid" && !c.expired && (
                      <button className="rounded border border-cyan-500/50 px-2 py-1 text-cyan-300" onClick={() => renew(c.serial)}>Renew</button>
                    )}
                    {c.status === "valid" && (
                      <button className="rounded border border-red-500/50 px-2 py-1 text-red-300" onClick={() => revoke(c.serial)}>Revoke</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!shown.length && <Empty>No certificates match these filters.</Empty>}
        </div>
      </Card>

      {detail && (
        <Modal title={`Certificate 0x${detail.serial}`} onClose={() => setDetail(null)} wide>
          <div className="grid gap-2 sm:grid-cols-2 text-xs mb-3">
            <div><span className="text-slate-500">Status:</span> <StatusBadge c={detail} /></div>
            <div><span className="text-slate-500">CA:</span> {detail.caName || "-"} <span className="mono text-slate-500">{detail.caSelection || ""}</span></div>
            <div><span className="text-slate-500">SANs:</span> {(detail.sanDomains || []).join(", ")}</div>
            <div><span className="text-slate-500">Issued via:</span> {detail.issuedViaTokenName || "—"}</div>
            <div><span className="text-slate-500">Issued:</span> {detail.issuedAt ? new Date(detail.issuedAt).toLocaleString() : "-"}</div>
            <div><span className="text-slate-500">Expires:</span> {detail.expiresAt ? new Date(detail.expiresAt).toLocaleString() : "-"} ({detail.daysRemaining ?? "?"}d)
              {detail.expiresAtEstimated && <span className="text-amber-300"> (estimated)</span>}</div>
            <div className="sm:col-span-2"><span className="text-slate-500">SHA-256:</span> <span className="mono text-cyan-300 break-all">{detail.sha256Fingerprint || "—"}</span></div>
            <div className="sm:col-span-2"><span className="text-slate-500">Files:</span> leaf {detail.hasLeafFile ? "✅" : "❌"} · chain {detail.hasChainFile ? "✅" : "❌"}
              {detail.supersededBy && <> · superseded by <span className="mono">0x{detail.supersededBy}</span></>}</div>
          </div>
          <div className="flex gap-2 mb-3">
            <Btn color="outline" className="text-xs" onClick={() => download(detail.serial, "leaf")}>⬇ Leaf PEM</Btn>
            <Btn color="outline" className="text-xs" onClick={() => download(detail.serial, "chain")}>⬇ Full chain</Btn>
            {detail.status === "valid" && <Btn color="danger" className="text-xs" onClick={() => { setDetail(null); revoke(detail.serial); }}>Revoke</Btn>}
          </div>
          <label className="text-xs text-slate-500">OpenSSL text</label>
          <pre className="mt-1 max-h-80 overflow-auto rounded-lg bg-black p-3 text-[11px] text-sky-300 mono">{detail.opensslText || "unavailable"}</pre>
        </Modal>
      )}
    </div>
  );
}
