import { useState } from "react";
import { apiFetch, downloadBlob, errText } from "./api";
import { Btn, Field, Modal, inp, useToast } from "./ui";

const PRESET_CAS = [
  { name: "int-server", desc: "Web / TLS / ACME" },
  { name: "int-wifi", desc: "RADIUS / 802.1X" },
  { name: "int-iot", desc: "Devices / MQTT" },
];

export default function Wizard({ onClose, initialPassword }) {
  const toast = useToast();
  const [form, setForm] = useState({
    org: "Enterprise", country: "US", state: "California", city: "San Francisco",
    keySize: "4096", rootDays: "7300", intDays: "3650",
  });
  const [picked, setPicked] = useState(["int-server", "int-wifi", "int-iot"]);
  const [custom, setCustom] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const toggle = (n) => setPicked((p) => (p.includes(n) ? p.filter((x) => x !== n) : [...p, n]));

  async function generate() {
    const names = [...picked];
    if (custom.trim()) {
      const c = custom.trim().toLowerCase().replace(/[^a-z0-9-_]/g, "");
      if (c && !names.includes(c)) names.push(c);
    }
    if (!names.length) return toast("Select at least one intermediate CA", true);
    setBusy(true);
    try {
      const res = await apiFetch("/api/auth/onboarding-generate-pki", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          orgName: form.org, country: form.country, state: form.state, city: form.city,
          keySize: form.keySize, rootDays: parseInt(form.rootDays, 10) || 7300,
          intDays: parseInt(form.intDays, 10) || 3650, intermediates: names.slice(0, 5),
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (data.success) {
        setResult(data);
        toast(`PKI generated: Root + ${data.intermediates.length} intermediate(s). Download the Root key NOW.`);
      } else toast(errText(data, "Generation failed"), true);
    } catch (e) {
      toast(e.message, true);
    }
    setBusy(false);
  }

  async function finish() {
    try {
      await apiFetch("/api/auth/complete-setup", { method: "POST" });
    } catch {}
    onClose();
  }

  return (
    <Modal title="🎉 Welcome to Enterprise PKI Signer" onClose={finish} wide>
      <p className="text-sm text-slate-400 mb-4">First-time setup — your admin password was generated on boot.</p>
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 mb-4">
        <div className="text-sm font-bold text-amber-400 mb-1">🔐 Initial admin password</div>
        <div className="flex items-center justify-between gap-2 rounded-lg bg-black px-3 py-2 mono text-cyan-300 text-sm">
          <span>{initialPassword || "Already set — use your ADMIN_PASSWORD (Coolify env)."}</span>
          {initialPassword && (
            <button className="rounded bg-slate-800 px-2 py-1 text-xs"
              onClick={() => { navigator.clipboard.writeText(initialPassword); toast("Password copied"); }}>
              Copy
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
        <Field label="Organization"><input value={form.org} onChange={set("org")} className={inp} /></Field>
        <Field label="Country (2-letter)"><input value={form.country} onChange={set("country")} maxLength={2} className={inp} /></Field>
        <Field label="State / Province"><input value={form.state} onChange={set("state")} className={inp} /></Field>
        <Field label="City"><input value={form.city} onChange={set("city")} className={inp} /></Field>
        <Field label="Key size">
          <select value={form.keySize} onChange={set("keySize")} className={inp}>
            <option value="2048">2048-bit (fast)</option>
            <option value="3072">3072-bit</option>
            <option value="4096">4096-bit (recommended)</option>
          </select>
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Root validity (days)"><input value={form.rootDays} onChange={set("rootDays")} type="number" className={inp} /></Field>
          <Field label="Intermediate validity"><input value={form.intDays} onChange={set("intDays")} type="number" className={inp} /></Field>
        </div>
      </div>

      <div className="rounded-xl border border-slate-700 p-4 mb-3">
        <div className="text-sm font-bold mb-2">Intermediate Signing CAs to create</div>
        {PRESET_CAS.map((c) => (
          <label key={c.name} className="flex items-center gap-2 py-1 text-sm cursor-pointer">
            <input type="checkbox" checked={picked.includes(c.name)} onChange={() => toggle(c.name)} className="accent-cyan-500" />
            <span className="mono font-semibold">{c.name}</span>
            <span className="text-slate-400 text-xs">— {c.desc}</span>
          </label>
        ))}
        <div className="mt-2 flex gap-2">
          <input value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="Custom name (optional, e.g. int-vpn)"
            className={inp} />
        </div>
        <p className="mt-2 text-[11px] text-slate-500">First selected becomes the active signer. All keys stored AES-256-GCM encrypted; Root key is handed to you once and shredded server-side.</p>
      </div>

      <Btn color="cyan" onClick={generate} disabled={busy} className="w-full py-2.5">
        {busy ? "Generating RSA PKI…" : result ? "✅ Generated — regenerate?" : "Generate PKI & Auto-Configure Signer"}
      </Btn>

      {result && (
        <div className="mt-4 rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
          <h4 className="font-bold text-emerald-400 mb-2">✅ PKI generated — download Root key NOW</h4>
          <div className="flex flex-col gap-2">
            <button className="rounded-lg bg-red-500 px-3 py-2 text-sm font-semibold text-white"
              onClick={() => downloadBlob("root-ca.key.pem", result.rootKeyPem)}>
              🛡️ Download ROOT private key (keep offline!)
            </button>
            <button className="rounded-lg border border-slate-600 px-3 py-2 text-sm"
              onClick={() => downloadBlob("root-ca.cert.pem", result.rootCertPem)}>
              📄 Download Root certificate
            </button>
            {result.intermediates.map((ca) => (
              <button key={ca.name} className="rounded-lg border border-slate-600 px-3 py-2 text-sm text-left"
                onClick={() => downloadBlob(`${ca.name}-chain.crt`, ca.chainPem)}>
                📦 Download {ca.name} chain <span className="text-slate-500">({ca.name}-chain.crt)</span>
              </button>
            ))}
          </div>
          <p className="mt-2 text-xs text-red-300">Move root-ca.key.pem to cold storage. The server has deleted its copy.</p>
        </div>
      )}

      <div className="mt-4 flex justify-end">
        <Btn color="cyan" onClick={finish}>Proceed to Dashboard →</Btn>
      </div>
    </Modal>
  );
}
