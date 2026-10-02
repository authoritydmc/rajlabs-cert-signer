import { useEffect, useState } from "react";
import { apiJson, authHeaders, downloadBlob, errText } from "../api";
import { Btn, Card, DaysSelector, Empty, Field, Modal, inp, useToast } from "../ui";

function StatusBadge({ t }) {
  return t.status === "active"
    ? <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">active</span>
    : <span className="rounded bg-red-500/15 px-2 py-0.5 text-xs text-red-300">{t.status}</span>;
}

export default function Tokens() {
  const toast = useToast();
  const [tokens, setTokens] = useState([]);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(new Set());
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", days: "", scopes: ["sign", "revoke"] });
  const [created, setCreated] = useState(null);
  const [usage, setUsage] = useState(null);

  async function load() {
    const { data } = await apiJson("/api/admin/tokens", { headers: authHeaders() });
    setTokens(Array.isArray(data) ? data : []);
    setSel(new Set());
  }
  useEffect(() => {
    load();
  }, []);

  const rows = tokens.filter((t) =>
    !q || `${t.name} ${t.token} ${t.status}`.toLowerCase().includes(q.toLowerCase()));

  const toggleScope = (s) =>
    setForm((f) => ({ ...f, scopes: f.scopes.includes(s) ? f.scopes.filter((x) => x !== s) : [...f.scopes, s] }));

  async function create() {
    if (!form.name.trim()) return toast("Token name is required", true);
    let expiresAt = null;
    if (form.days.trim()) {
      const n = parseInt(form.days.trim(), 10);
      if (!n || n < 1) return toast("Expiry must be a positive number of days", true);
      expiresAt = new Date(Date.now() + n * 86400000).toISOString();
    }
    if (!form.scopes.length) return toast("Select at least one scope", true);
    const { data } = await apiJson("/api/admin/tokens", {
      method: "POST", headers: authHeaders(),
      body: JSON.stringify({ name: form.name.trim(), expiresAt, scopes: form.scopes }),
    });
    if (data.success) {
      setCreated(data.token); // full secret shown ONCE
      setForm({ name: "", days: "", scopes: ["sign", "revoke"] });
      load();
    } else toast(errText(data, "Token creation failed"), true);
  }

  async function action(id, act) {
    await apiJson(`/api/admin/tokens/${id}/${act}`, { method: "POST", headers: authHeaders() });
    load();
  }
  async function remove(id) {
    if (!confirm("Permanently delete this token? (Prefer Revoke for audit trail.)")) return;
    await apiJson(`/api/admin/tokens/${id}`, { method: "DELETE", headers: authHeaders() });
    load();
  }
  async function bulk(act) {
    if (!sel.size) return toast("Select tokens first");
    if (!confirm(`${act} ${sel.size} token(s)?`)) return;
    const { data } = await apiJson("/api/admin/tokens/bulk", {
      method: "POST", headers: authHeaders(), body: JSON.stringify({ ids: [...sel], action: act }),
    });
    if (data.success) toast(`${act}: ${data.affected}`);
    else toast(errText(data), true);
    load();
  }
  async function showUsage(id) {
    const { data } = await apiJson(`/api/admin/tokens/${id}/usage`, { headers: authHeaders() });
    if (!data.success) return toast(errText(data), true);
    setUsage(data);
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div>
          <h1 className="text-2xl font-extrabold">API Tokens</h1>
          <p className="text-sm text-slate-400">Usage-tracked keys for CI/CD, Traefik, FreeRADIUS backend.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Btn color="outline" onClick={() => bulk("revoke")}>Revoke sel.</Btn>
          <Btn color="outline" onClick={() => bulk("restore")}>Restore sel.</Btn>
          <Btn color="danger" onClick={() => bulk("delete")}>Delete sel.</Btn>
          <Btn color="cyan" onClick={() => { setCreated(null); setShowCreate(true); }}>+ New Token</Btn>
        </div>
      </div>

      <Card className="mb-4">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="🔍 Filter by name, key, status…"
          className={`${inp} max-w-md`} />
      </Card>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead><tr className="text-slate-400">
              <th className="p-2"><input type="checkbox" checked={rows.length > 0 && rows.every((t) => sel.has(t.id))}
                onChange={(e) => setSel(e.target.checked ? new Set(rows.map((t) => t.id)) : new Set())} /></th>
              <th className="p-2">Name / scopes / expiry</th><th className="p-2">Key</th><th className="p-2">Status</th>
              <th className="p-2" title="Certificates issued with this key">Certs</th>
              <th className="p-2" title="Sign API calls made with this key">Uses</th>
              <th className="p-2">Last access</th><th className="p-2">Actions</th>
            </tr></thead>
            <tbody>
              {rows.map((t) => (
                <tr key={t.id} className="border-t border-slate-800">
                  <td className="p-2"><input type="checkbox" className="accent-cyan-500" checked={sel.has(t.id)}
                    onChange={() => setSel((prev) => { const n = new Set(prev); if (n.has(t.id)) n.delete(t.id); else n.add(t.id); return n; })} /></td>
                  <td className="p-2 font-semibold">{t.name}
                    <div className="text-[11px] font-normal text-slate-500">created {t.createdAt ? new Date(t.createdAt).toLocaleDateString() : "-"}</div>
                    <div className="text-[11px] font-normal text-slate-500">scopes: {(t.scopes || []).join(", ")}</div>
                    <div className={`text-[11px] font-normal ${t.expiresAt ? "text-amber-300" : "text-slate-600"}`}>
                      {t.expiresAt ? "expires " + new Date(t.expiresAt).toLocaleDateString() : "no expiry"}</div></td>
                  <td className="p-2 mono text-xs break-all"><span title={t.token}>{t.token.slice(0, 18)}…</span></td>
                  <td className="p-2"><StatusBadge t={t} />
                    {t.revokedAt && <div className="text-[10px] text-slate-500">{new Date(t.revokedAt).toLocaleDateString()}</div>}</td>
                  <td className="p-2 text-center font-bold text-cyan-300">{t.certsIssued ?? 0}</td>
                  <td className="p-2 text-center">{t.usageCount ?? 0}</td>
                  <td className="p-2 text-xs text-slate-400">
                    {t.lastUsedAt ? new Date(t.lastUsedAt).toLocaleString() : <span className="text-slate-600">never</span>}
                    {t.lastUsedCN && <><br /><span className="mono text-cyan-300">{t.lastUsedCN}</span></>}</td>
                  <td className="p-2 whitespace-nowrap text-xs flex flex-wrap gap-1">
                    <button className="rounded border border-slate-600 px-2 py-1" onClick={() => showUsage(t.id)}>Usage</button>
                    {t.revoked
                      ? <button className="rounded border border-emerald-500/50 px-2 py-1 text-emerald-300" onClick={() => action(t.id, "restore")}>Restore</button>
                      : <button className="rounded border border-amber-500/50 px-2 py-1 text-amber-300" onClick={() => action(t.id, "revoke")}>Revoke</button>}
                    <button className="rounded border border-red-500/50 px-2 py-1 text-red-300" onClick={() => remove(t.id)}>✕</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <Empty>No tokens match.</Empty>}
        </div>
      </Card>

      {usage && (
        <Modal title={`Usage: ${usage.token.name} — ${usage.certificates.length} cert(s)`} onClose={() => setUsage(null)}>
          {usage.certificates.length ? usage.certificates.map((c) => (
            <div key={c.serial} className="border-t border-slate-800 py-1 mono text-xs">
              0x{c.serial} · {(c.sanDomains || []).join(", ")} · {c.status}
            </div>
          )) : <span className="text-slate-500 text-sm">No certificates issued with this key yet.</span>}
        </Modal>
      )}

      {showCreate && (
        <Modal title="🔑 Create API token" onClose={() => { setShowCreate(false); setCreated(null); }}>
          {!created ? (
            <>
              <div className="mb-3"><Field label="Token name (e.g. FreeRADIUS backend, Traefik)">
                <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="FreeRADIUS backend" className={inp} autoFocus />
              </Field></div>
              <div className="mb-3">
                <Field label="Token Expiration">
                  <DaysSelector
                    value={form.days}
                    onChange={(d) => setForm({ ...form, days: d })}
                    allowEmpty={true}
                    emptyLabel="Never · No Expiration (Permanent)"
                    presets={[
                      { label: "30 Days · Short-term Access", value: "30" },
                      { label: "90 Days · Quarterly Key Rotation", value: "90" },
                      { label: "180 Days · 6 Months", value: "180" },
                      { label: "1 Year · Annual Rotation (365d)", value: "365" },
                    ]}
                  />
                </Field>
              </div>
              <div className="mb-4">
                <span className="text-xs font-semibold text-slate-300">Scopes</span>
                <div className="mt-1 flex gap-4">
                  {["sign", "revoke"].map((s) => (
                    <label key={s} className="flex items-center gap-2 text-sm cursor-pointer">
                      <input type="checkbox" checked={form.scopes.includes(s)} onChange={() => toggleScope(s)} className="accent-cyan-500" />
                      <span className="mono">{s}</span>
                    </label>
                  ))}
                </div>
              </div>
              <Btn color="cyan" onClick={create} className="w-full py-2.5">Generate Token</Btn>
            </>
          ) : (
            <>
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 mb-3">
                <div className="text-sm font-bold text-emerald-400 mb-1">✅ Token created — copy it now, it won't be shown in full again</div>
                <div className="rounded-lg bg-black px-3 py-2 mono text-cyan-300 text-sm break-all">{created.token}</div>
                <div className="mt-2 flex gap-2">
                  <Btn color="outline" className="text-xs" onClick={() => { navigator.clipboard.writeText(created.token); toast("API key copied"); }}>📋 Copy</Btn>
                  <Btn color="outline" className="text-xs" onClick={() => downloadBlob(`${created.name}-apikey.txt`, created.token, "text/plain")}>⬇ Save .txt</Btn>
                </div>
              </div>
              <Btn color="cyan" onClick={() => { setShowCreate(false); setCreated(null); }} className="w-full">Done</Btn>
            </>
          )}
        </Modal>
      )}
    </div>
  );
}
