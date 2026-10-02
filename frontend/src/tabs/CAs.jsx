import { useEffect, useState } from "react";
import { apiFetch, apiJson, authHeaders, errText } from "../api";
import { Btn, Card, Empty, Field, Modal, inp, useToast } from "../ui";

// ─── PEM Cert Parser (client-side, no deps) ─────────────────────────────────
function parsePemCert(pem) {
  if (!pem) return null;
  try {
    // Extract base64 body
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

    // SHA-256 fingerprint via SubtleCrypto (async, handled separately)
    // We'll parse key fields from the PEM text itself using regex patterns
    // and trust the backend for anything that needs DER parsing
    const lines = pem.split("\n");

    // Extract text block
    return { raw: pem, der, b64 };
  } catch {
    return null;
  }
}

async function sha256Fingerprint(pem) {
  try {
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const hash = await crypto.subtle.digest("SHA-256", der);
    const arr = Array.from(new Uint8Array(hash));
    return arr.map((b) => b.toString(16).padStart(2, "0")).join(":").toUpperCase();
  } catch {
    return null;
  }
}

async function sha1Fingerprint(pem) {
  try {
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const hash = await crypto.subtle.digest("SHA-1", der);
    const arr = Array.from(new Uint8Array(hash));
    return arr.map((b) => b.toString(16).padStart(2, "0")).join(":").toUpperCase();
  } catch {
    return null;
  }
}

// Parse validity dates from PEM text (regex approach — works for standard ASN.1 certs)
function extractPemTextFields(pem) {
  // We ask the backend /api/admin/inspect-cert for parsed fields instead
  return null;
}

// ─── Certificate Inspector Modal ────────────────────────────────────────────
function CertInspector({ ca, onClose }) {
  const [fp256, setFp256] = useState(null);
  const [fp1, setFp1] = useState(null);
  const [rootFp256, setRootFp256] = useState(null);
  const [inspect, setInspect] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function compute() {
      setLoading(true);
      const [f256, f1, rf256] = await Promise.all([
        sha256Fingerprint(ca.certPem),
        sha1Fingerprint(ca.certPem),
        ca.rootCertPem ? sha256Fingerprint(ca.rootCertPem) : Promise.resolve(null),
      ]);
      setFp256(f256);
      setFp1(f1);
      setRootFp256(rf256);

      // Try fetching parsed fields from backend
      try {
        const { data } = await apiJson(`/api/admin/intermediate-cas/${ca.id}/inspect`, {
          headers: authHeaders(),
        });
        if (data && !data.error) setInspect(data);
      } catch {}
      setLoading(false);
    }
    compute();
  }, [ca]);

  const copy = (text) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  const fmtDate = (iso) => {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString(undefined, {
        year: "numeric", month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit", timeZoneName: "short",
      });
    } catch { return iso; }
  };

  const daysLeft = (iso) => {
    if (!iso) return null;
    const diff = new Date(iso) - Date.now();
    return Math.floor(diff / 86400000);
  };

  const DaysLeftBadge = ({ iso }) => {
    const d = daysLeft(iso);
    if (d === null) return null;
    const color = d < 0 ? "bg-red-500/20 text-red-300 border-red-500/40"
      : d < 90 ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
      : "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
    const label = d < 0 ? `Expired ${Math.abs(d)}d ago` : `${d} days left`;
    return <span className={`rounded border px-2 py-0.5 text-xs font-medium ${color}`}>{label}</span>;
  };

  const Row = ({ label, value, mono, copy: copyable }) => (
    <div className="flex items-start gap-2 py-1.5 border-b border-slate-800/60 last:border-0">
      <span className="w-36 shrink-0 text-[11px] uppercase tracking-wide text-slate-500 pt-0.5">{label}</span>
      <span className={`flex-1 text-sm text-slate-200 break-all leading-relaxed ${mono ? "font-mono text-xs" : ""}`}>
        {value ?? "—"}
      </span>
      {copyable && value && (
        <button
          onClick={() => copy(value)}
          className="shrink-0 rounded bg-slate-800 hover:bg-slate-700 px-2 py-0.5 text-[10px] text-slate-300 transition"
        >
          Copy
        </button>
      )}
    </div>
  );

  const Section = ({ title, children }) => (
    <div className="mb-4">
      <div className="text-[10px] uppercase tracking-widest text-cyan-500/70 font-bold mb-2 pl-1">{title}</div>
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 px-3 py-1">{children}</div>
    </div>
  );

  return (
    <Modal title={`🔍 Certificate Inspector · ${ca.name}`} onClose={onClose} wide>
      {loading ? (
        <div className="text-center py-12 text-slate-400 text-sm">
          <div className="text-3xl mb-3 animate-pulse">🔬</div>
          Computing fingerprints & parsing X.509 fields…
        </div>
      ) : (
        <div className="space-y-0">
          {/* Identity */}
          <Section title="Subject Identity">
            {inspect ? (
              <>
                <Row label="Common Name" value={inspect.subject?.CN} />
                <Row label="Organization" value={inspect.subject?.O} />
                <Row label="Country" value={inspect.subject?.C} />
                <Row label="State / Province" value={inspect.subject?.ST} />
                <Row label="City / Locality" value={inspect.subject?.L} />
              </>
            ) : (
              <Row label="CA Name" value={ca.name} />
            )}
          </Section>

          {/* Validity */}
          <Section title="Validity Period">
            {inspect ? (
              <>
                <Row label="Not Before" value={fmtDate(inspect.not_before)} />
                <div className="flex items-start gap-2 py-1.5 border-b border-slate-800/60">
                  <span className="w-36 shrink-0 text-[11px] uppercase tracking-wide text-slate-500 pt-0.5">Not After</span>
                  <span className="flex-1 text-sm text-slate-200">{fmtDate(inspect.not_after)}</span>
                  <DaysLeftBadge iso={inspect.not_after} />
                </div>
                <Row label="Serial Number" value={inspect.serial} mono copy />
              </>
            ) : (
              <div className="py-2 text-xs text-slate-500">
                Backend X.509 parser unavailable — fingerprints computed client-side.
              </div>
            )}
          </Section>

          {/* Key Info */}
          {inspect && (
            <Section title="Key Information">
              <Row label="Key Algorithm" value={inspect.key_type} />
              <Row label="Key Size" value={inspect.key_bits ? `${inspect.key_bits} bits` : undefined} />
              <Row label="Signature Alg" value={inspect.sig_alg} />
            </Section>
          )}

          {/* Extensions */}
          {inspect && (inspect.key_usage?.length || inspect.ext_key_usage?.length || inspect.sans?.length) && (
            <Section title="Extensions">
              {inspect.key_usage?.length > 0 && (
                <Row label="Key Usage" value={inspect.key_usage.join(", ")} />
              )}
              {inspect.ext_key_usage?.length > 0 && (
                <Row label="Extended Key Usage" value={inspect.ext_key_usage.join(", ")} />
              )}
              {inspect.is_ca !== undefined && (
                <Row label="CA:TRUE" value={inspect.is_ca ? "✅ Yes (Certificate Authority)" : "❌ No"} />
              )}
              {inspect.path_len !== undefined && inspect.path_len !== null && (
                <Row label="PathLen Constraint" value={String(inspect.path_len)} />
              )}
              {inspect.sans?.length > 0 && (
                <Row label="SANs" value={inspect.sans.join(", ")} />
              )}
            </Section>
          )}

          {/* CDP / AIA */}
          {inspect && (inspect.crl_urls?.length || inspect.ocsp_urls?.length) && (
            <Section title="Distribution Points">
              {inspect.crl_urls?.map((u, i) => (
                <Row key={i} label={i === 0 ? "CRL URL" : ""} value={u} mono copy />
              ))}
              {inspect.ocsp_urls?.map((u, i) => (
                <Row key={i} label={i === 0 ? "OCSP URL" : ""} value={u} mono copy />
              ))}
            </Section>
          )}

          {/* Fingerprints */}
          <Section title="Fingerprints (Intermediate CA)">
            <Row label="SHA-256" value={fp256} mono copy />
            <Row label="SHA-1" value={fp1} mono copy />
          </Section>

          {/* Root CA */}
          {ca.rootCertPem && (
            <Section title="Root CA Fingerprint">
              <div className="flex items-start gap-2 py-1.5">
                <span className="w-36 shrink-0 text-[11px] uppercase tracking-wide text-slate-500 pt-0.5">SHA-256</span>
                <span className="flex-1 font-mono text-xs text-emerald-300 break-all">{rootFp256 ?? "Computing…"}</span>
                {rootFp256 && (
                  <button onClick={() => copy(rootFp256)} className="shrink-0 rounded bg-slate-800 hover:bg-slate-700 px-2 py-0.5 text-[10px] text-slate-300 transition">
                    Copy
                  </button>
                )}
              </div>
              <div className="mt-1.5 mb-1 flex items-center gap-2 rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 text-[11px] text-amber-300">
                🔒 Root CA is air-gapped. Private key was never stored server-side after initial generation.
              </div>
            </Section>
          )}

          {/* Raw PEM */}
          <Section title="Raw PEM (Intermediate Certificate)">
            <div className="relative">
              <pre className="text-[10px] text-emerald-300/80 leading-relaxed break-all whitespace-pre-wrap max-h-40 overflow-y-auto custom-scroll">
                {ca.certPem}
              </pre>
              <button
                onClick={() => copy(ca.certPem)}
                className="absolute top-2 right-2 rounded bg-slate-700 hover:bg-slate-600 px-2.5 py-1 text-[10px] text-slate-200 transition"
              >
                Copy PEM
              </button>
            </div>
          </Section>
        </div>
      )}
      <div className="mt-4 pt-3 border-t border-slate-800 flex justify-end">
        <Btn color="ghost" onClick={onClose}>Close</Btn>
      </div>
    </Modal>
  );
}

// ─── Main CAs Component ──────────────────────────────────────────────────────
export default function CAs({ onChanged, openWizard }) {
  const toast = useToast();
  const [cas, setCas] = useState([]);
  const [counts, setCounts] = useState({});
  const [crlOk, setCrlOk] = useState(null);
  const [showImport, setShowImport] = useState(false);
  const [loading, setLoading] = useState(true);
  const [inspecting, setInspecting] = useState(null); // CA object to inspect
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
      certs.forEach((c) => { per[c.caName] = (per[c.caName] || 0) + 1; });
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
          <p className="text-sm text-slate-400">Keys are encrypted at rest with AES-256-GCM. Click 🔍 to inspect any certificate.</p>
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
              {loading && (
                <tr>
                  <td colSpan={5} className="text-center py-10 text-slate-500 text-sm">
                    <span className="animate-pulse">Loading CAs…</span>
                  </td>
                </tr>
              )}
              {!loading && cas.map((ca) => (
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
                    <button
                      className="rounded border border-slate-600 hover:border-cyan-500/60 hover:bg-cyan-500/10 px-2.5 py-1 text-xs text-slate-300 hover:text-cyan-300 transition mr-1.5"
                      onClick={() => setInspecting(ca)}
                      title="Inspect X.509 certificate details"
                    >
                      🔍 Inspect
                    </button>
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

      {inspecting && (
        <CertInspector ca={inspecting} onClose={() => setInspecting(null)} />
      )}
    </div>
  );
}
