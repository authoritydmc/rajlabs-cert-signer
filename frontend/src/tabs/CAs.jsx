import { useEffect, useState } from "react";
import { apiFetch, apiJson, authHeaders, errText } from "../api";
import { Btn, Card, Field, inp, useToast } from "../ui";

export default function CAs({ onChanged }) {
  const toast = useToast();
  const [cas, setCas] = useState([]);
  const [counts, setCounts] = useState({});
  const [crlOk, setCrlOk] = useState(null);
  const [showImport, setShowImport] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", root: "", cert: "", key: "", active: true });

  async function load() {
    const [{ data: list }, certsRes, stRes] = await Promise.all([
      apiJson("/api/admin/intermediate-cas", { headers: authHeaders() }),
      apiJson("/api/admin/certificates", { headers: authHeaders() }).catch(() => ({ data: [] })),
      apiJson("/api/v1/status").catch(() => ({ data: null })),
    ]);
    setCas(Array.isArray(list) ? list : []);
    const certs = Array.isArray(certsRes.data) ? certsRes.data : certsRes.data.entries || [];
    const per = {};
    certs.forEach((c) => {
      per[c.caName] = (per[c.caName] || 0) + 1;
    });
    setCounts(per);
    setCrlOk(stRes.data?.crl?.exists ?? null);
  }
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function activate(id) {
    await apiFetch(`/api/admin/intermediate-cas/${id}/activate`, { method: "POST", headers: authHeaders() });
    load();
    onChanged();
  }
  async function remove(id) {
    if (!confirm("Delete this CA? Existing certs stay for audit but cannot be re-signed by it.")) return;
    const r = await apiFetch(`/api/admin/intermediate-cas/${id}`, { method: "DELETE", headers: authHeaders() });
    const data = await r.json().catch(() => ({}));
    if (!data.success) toast(errText(data), true);
    load();
    onChanged();
  }
  async function submit() {
    const r = await apiFetch("/api/admin/intermediate-cas", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        name: form.name, description: form.description, setActive: form.active,
        rootCertPem: form.root, certPem: form.cert, keyPem: form.key,
      }),
    });
    const d = await r.json().catch(() => ({}));
    if (d.success || r.ok) {
      setShowImport(false);
      setForm({ name: "", description: "", root: "", cert: "", key: "", active: true });
      load();
      onChanged();
    } else toast(errText(d, "Import failed"), true);
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div>
          <h1 className="text-2xl font-extrabold">Intermediate CAs</h1>
          <p className="text-sm text-slate-400">Keys encrypted at rest (AES-256-GCM).</p>
        </div>
        <Btn color="cyan" onClick={() => setShowImport((s) => !s)}>+ Import CA</Btn>
      </div>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead><tr className="text-slate-400">
              <th className="p-2">ID</th><th className="p-2">Desc</th><th className="p-2">Key</th>
              <th className="p-2">Status</th><th className="p-2">Actions</th>
            </tr></thead>
            <tbody>
              {cas.map((ca) => (
                <tr key={ca.id} className="border-t border-slate-800">
                  <td className="p-2 font-bold">{ca.name}
                    <div className="text-[11px] font-normal text-slate-500">{counts[ca.name] || 0} cert(s) signed</div></td>
                  <td className="p-2 text-slate-400">{ca.description || "-"}</td>
                  <td className="p-2"><span className="rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">Encrypted</span></td>
                  <td className="p-2">
                    {ca.isActive
                      ? <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-300">Active</span>
                      : <span className="text-slate-500 text-xs">Standby</span>}
                    {ca.isActive && crlOk !== null && (
                      <div className={`text-[11px] ${crlOk ? "text-emerald-400" : "text-amber-300"}`}>
                        {crlOk ? "CRL ✅" : "CRL pending"}
                      </div>
                    )}
                  </td>
                  <td className="p-2 whitespace-nowrap">
                    {!ca.isActive && <Btn color="ghost" className="px-2 py-1 text-xs mr-1" onClick={() => activate(ca.id)}>Make active</Btn>}
                    <button className="rounded border border-red-500/50 px-2 py-1 text-xs text-red-300" onClick={() => remove(ca.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {showImport && (
        <Card className="mt-4 border-cyan-500/40">
          <h3 className="font-bold text-cyan-300 mb-3">Import Intermediate CA</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Identifier (int-server…)"><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inp} /></Field>
            <Field label="Description"><input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inp} /></Field>
          </div>
          <div className="mt-2"><Field label="Root cert PEM"><textarea value={form.root} onChange={(e) => setForm({ ...form, root: e.target.value })} rows={2} className={`${inp} mono text-xs`} /></Field></div>
          <div className="mt-2"><Field label="Intermediate cert PEM"><textarea value={form.cert} onChange={(e) => setForm({ ...form, cert: e.target.value })} rows={2} className={`${inp} mono text-xs`} /></Field></div>
          <div className="mt-2"><Field label="Intermediate key PEM"><textarea value={form.key} onChange={(e) => setForm({ ...form, key: e.target.value })} rows={2} className={`${inp} mono text-xs`} /></Field></div>
          <label className="mt-2 text-xs flex items-center gap-2">
            <input type="checkbox" checked={form.active} onChange={(e) => setForm({ ...form, active: e.target.checked })} className="accent-cyan-500" /> Set as active
          </label>
          <div className="mt-3"><Btn color="cyan" onClick={submit}>Save & Encrypt</Btn></div>
        </Card>
      )}
    </div>
  );
}
