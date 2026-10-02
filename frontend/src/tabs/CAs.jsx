import { useEffect, useState } from "react";
import { apiFetch, apiJson, authHeaders, errText } from "../api";
import { Btn, Card, Empty, Field, inp, useToast } from "../ui";

export default function CAs({ onChanged, openWizard }) {
  const toast = useToast();
  const [cas, setCas] = useState([]);
  const [counts, setCounts] = useState({});
  const [crlOk, setCrlOk] = useState(null);
  const [showImport, setShowImport] = useState(false);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ name: "", description: "", root: "", cert: "", key: "", active: true });

  async function load() {
    setLoading(true);
    try {
      const [{ res: casRes, data: list }, certsRes, stRes] = await Promise.all([
        apiJson("/api/admin/intermediate-cas", { headers: authHeaders() }),
        apiJson("/api/admin/certificates", { headers: authHeaders() }).catch(() => ({ data: [] })),
        apiJson("/api/v1/status").catch(() => ({ data: null })),
      ]);
      if (Array.isArray(list)) {
        setCas(list);
      } else {
        setCas([]);
        if (list?.error && casRes?.status !== 401) {
          toast(errText(list, "Failed to load Intermediate CAs"), true);
        }
      }
      const certs = Array.isArray(certsRes.data) ? certsRes.data : certsRes.data?.entries || [];
      const per = {};
      certs.forEach((c) => {
        per[c.caName] = (per[c.caName] || 0) + 1;
      });
      setCounts(per);
      setCrlOk(stRes.data?.crl?.exists ?? null);
    } catch (e) {
      toast(e.message, true);
    }
    setLoading(false);
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
        name: form.name,
        description: form.description,
        setActive: form.active,
        rootCertPem: form.root,
        certPem: form.cert,
        keyPem: form.key,
      }),
    });
    const d = await r.json().catch(() => ({}));
    if (d.success || r.ok) {
      setShowImport(false);
      setForm({ name: "", description: "", root: "", cert: "", key: "", active: true });
      load();
      onChanged();
      toast("Intermediate CA imported successfully.");
    } else {
      toast(errText(d, "Import failed"), true);
    }
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100">Intermediate Signing CAs</h1>
          <p className="text-sm text-slate-400">Keys are encrypted at rest with AES-256-GCM.</p>
        </div>
        <div className="flex gap-2">
          {openWizard && (
            <Btn color="ghost" onClick={openWizard} className="text-xs">
              🧙 Setup Wizard
            </Btn>
          )}
          <Btn color="cyan" onClick={() => setShowImport((s) => !s)}>
            + Import CA
          </Btn>
        </div>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="text-slate-400 border-b border-slate-800 text-xs uppercase tracking-wider">
                <th className="p-3">ID / Name</th>
                <th className="p-3">Description</th>
                <th className="p-3">Key Storage</th>
                <th className="p-3">Status</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {cas.map((ca) => (
                <tr key={ca.id} className="border-t border-slate-800/80 hover:bg-slate-800/20">
                  <td className="p-3 font-bold text-slate-100">
                    <span className="mono">{ca.name}</span>
                    <div className="text-[11px] font-normal text-slate-500">
                      {counts[ca.name] || 0} cert(s) signed
                    </div>
                  </td>
                  <td className="p-3 text-slate-400">{ca.description || "—"}</td>
                  <td className="p-3">
                    <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-xs text-emerald-300 font-medium">
                      🔒 AES-256-GCM
                    </span>
                  </td>
                  <td className="p-3">
                    {ca.isActive ? (
                      <span className="rounded bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 text-xs text-cyan-300 font-semibold">
                        ● Active Signer
                      </span>
                    ) : (
                      <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
                        Standby
                      </span>
                    )}
                    {ca.isActive && crlOk !== null && (
                      <div className={`mt-1 text-[11px] ${crlOk ? "text-emerald-400" : "text-amber-300"}`}>
                        {crlOk ? "CRL Active ✅" : "CRL pending generation"}
                      </div>
                    )}
                  </td>
                  <td className="p-3 text-right whitespace-nowrap">
                    {!ca.isActive && (
                      <Btn color="ghost" className="px-2.5 py-1 text-xs mr-1.5" onClick={() => activate(ca.id)}>
                        Make Active
                      </Btn>
                    )}
                    <button
                      className="rounded border border-red-500/50 hover:bg-red-500/20 px-2.5 py-1 text-xs text-red-300 transition"
                      onClick={() => remove(ca.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!loading && !cas.length && (
            <div className="py-8 px-4 text-center">
              <div className="text-3xl mb-2">🏛️</div>
              <h3 className="font-bold text-slate-300 mb-1">No Intermediate Signing CAs Found</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto mb-4">
                You need at least one Intermediate CA (such as <span className="mono">int-server</span>) to sign leaf certificates and serve ACME requests.
              </p>
              <div className="flex justify-center gap-3">
                {openWizard && (
                  <Btn color="cyan" onClick={openWizard} className="text-xs">
                    🧙 Launch Setup Wizard (1-Click Auto Gen)
                  </Btn>
                )}
                <Btn color="outline" onClick={() => setShowImport(true)} className="text-xs">
                  + Import Existing PEMs
                </Btn>
              </div>
            </div>
          )}
        </div>
      </Card>

      {showImport && (
        <Card className="mt-4 border-cyan-500/40 bg-slate-900/95">
          <h3 className="font-bold text-cyan-300 mb-1">Import Intermediate CA</h3>
          <p className="text-[11px] text-slate-400 mb-3">
            Paste the PEM blocks for your intermediate CA: <b>Intermediate Certificate</b> + <b>Private Key</b> + <b>Root Certificate</b>.
          </p>
          <div className="grid gap-3 sm:grid-cols-2 mb-3">
            <Field label="Identifier (e.g. int-server, int-wifi, int-iot)">
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="int-server"
                className={inp}
              />
            </Field>
            <Field label="Description">
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Web & TLS Signing Authority"
                className={inp}
              />
            </Field>
          </div>
          <div className="space-y-3">
            <div>
              <Field label="Root CA Certificate (PEM)">
                <textarea
                  value={form.root}
                  onChange={(e) => setForm({ ...form, root: e.target.value })}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  rows={2}
                  className={`${inp} mono text-xs`}
                />
              </Field>
            </div>
            <div>
              <Field label="Intermediate CA Certificate (PEM)">
                <textarea
                  value={form.cert}
                  onChange={(e) => setForm({ ...form, cert: e.target.value })}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  rows={2}
                  className={`${inp} mono text-xs`}
                />
              </Field>
            </div>
            <div>
              <Field label="Intermediate CA Private Key (PEM)">
                <textarea
                  value={form.key}
                  onChange={(e) => setForm({ ...form, key: e.target.value })}
                  placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                  rows={2}
                  className={`${inp} mono text-xs`}
                />
              </Field>
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between">
            <label className="text-xs flex items-center gap-2 cursor-pointer text-slate-300">
              <input
                type="checkbox"
                checked={form.active}
                onChange={(e) => setForm({ ...form, active: e.target.checked })}
                className="accent-cyan-500 h-4 w-4"
              />
              <span>Set as active signer immediately</span>
            </label>
            <div className="flex gap-2">
              <Btn color="ghost" className="text-xs" onClick={() => setShowImport(false)}>
                Cancel
              </Btn>
              <Btn color="cyan" className="text-xs" onClick={submit}>
                Save & Encrypt Key
              </Btn>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
