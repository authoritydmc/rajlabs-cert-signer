import { useState } from "react";
import { apiFetch, downloadBlob, errText } from "./api";
import { Btn, Field, Modal, inp, useToast } from "./ui";

// What each intermediate CA is for — shown in the wizard so admins pick knowingly.
const CA_TYPES = [
  {
    name: "int-server",
    title: "Web / TLS / ACME",
    for: "HTTPS websites & APIs, internal services, reverse proxies, ACME clients (Certbot, Traefik, Caddy).",
    clients: "Browsers, curl, Traefik, Nginx, Certbot",
    leafEx: "app.example.com (90 days)",
  },
  {
    name: "int-wifi",
    title: "WiFi / RADIUS (802.1X)",
    for: "WPA-Enterprise networks: EAP-TLS server certificate for FreeRADIUS + client certificates for devices.",
    clients: "FreeRADIUS, WiFi APs, phones & laptops (EAP-TLS)",
    leafEx: "radius.example.com",
  },
  {
    name: "int-iot",
    title: "IoT / devices (MQTT)",
    for: "Mutual-TLS device identities for MQTT brokers and embedded fleets.",
    clients: "MQTT brokers, sensors, gateways",
    leafEx: "device-001.example.com",
  },
];

function Help({ text }) {
  return <p className="mt-1 text-[11px] leading-snug text-slate-500">{text}</p>;
}

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
    if (!names.length) return toast("Select at least one intermediate CA below", true);
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
      <p className="text-sm text-slate-400 mb-1">First-time setup — creates your Root CA plus the Signing CAs you tick below.</p>
      <p className="text-xs text-slate-500 mb-4">How it works: <b>1.</b> fill identity → <b>2.</b> pick intermediates → <b>3.</b> generate & download Root key once (server shreds its copy).</p>

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

      <div className="text-sm font-bold mb-2">Step 1 · Organization identity <span className="font-normal text-slate-500">(goes into your Root & intermediate certificate subjects)</span></div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-2">
        <div><Field label="Organization"><input value={form.org} onChange={set("org")} className={inp} /></Field>
          <Help text="Your company / lab name. Appears as O= in every CA certificate, e.g. O=RajLabs." /></div>
        <div><Field label="Country (2-letter)"><input value={form.country} onChange={set("country")} maxLength={2} className={inp} /></Field>
          <Help text="ISO code, e.g. US, IN, DE. Appears as C= in certificate subjects." /></div>
        <div><Field label="State / Province"><input value={form.state} onChange={set("state")} className={inp} /></Field>
          <Help text="Appears as ST=. Any text is fine for private PKI." /></div>
        <div><Field label="City / Locality"><input value={form.city} onChange={set("city")} className={inp} /></Field>
          <Help text="Appears as L=. Any text is fine for private PKI." /></div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
        <div><Field label="Key size">
          <select value={form.keySize} onChange={set("keySize")} className={inp}>
            <option value="2048">2048-bit (fast)</option>
            <option value="3072">3072-bit</option>
            <option value="4096">4096-bit (recommended)</option>
          </select></Field>
          <Help text="Bigger = stronger but slower. 4096-bit for CAs is the safe default; generation takes a few seconds." /></div>
        <div><Field label="Root validity (days)"><input value={form.rootDays} onChange={set("rootDays")} type="number" className={inp} /></Field>
          <Help text="Root lives offline for years. 7300 ≈ 20 years. You almost never rotate it." /></div>
        <div><Field label="Intermediate validity (days)"><input value={form.intDays} onChange={set("intDays")} type="number" className={inp} /></Field>
          <Help text="Signing CAs do the daily work. 3650 ≈ 10 years. Shorter = rotate sooner." /></div>
      </div>

      <div className="text-sm font-bold mb-2">Step 2 · Which Signing CAs do you need? <span className="font-normal text-slate-500">(tick 1–3; first ticked becomes active)</span></div>
      <div className="grid gap-2 sm:grid-cols-3 mb-2">
        {CA_TYPES.map((c) => (
          <label key={c.name} className={`rounded-xl border p-3 cursor-pointer transition ${picked.includes(c.name) ? "border-cyan-500 bg-cyan-500/10" : "border-slate-700 hover:border-slate-500"}`}>
            <div className="flex items-center gap-2">
              <input type="checkbox" checked={picked.includes(c.name)} onChange={() => toggle(c.name)} className="accent-cyan-500" />
              <span className="mono text-sm font-bold">{c.name}</span>
            </div>
            <div className="mt-1 text-xs font-semibold text-cyan-200">{c.title}</div>
            <div className="mt-1 text-[11px] text-slate-300">{c.for}</div>
            <div className="mt-1 text-[10px] text-slate-500">Typical clients: {c.clients}</div>
            <div className="mt-1 text-[10px] text-slate-500">Leaf example: <span className="mono">{c.leafEx}</span></div>
          </label>
        ))}
      </div>
      <div className="mb-1"><Field label="Custom intermediate (optional)">
        <input value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="e.g. int-vpn — for anything not covered above" className={inp} />
      </Field>
        <Help text="Names are lowercase letters, numbers, dashes. The Issue page's purpose routing (server/wifi/iot) only auto-maps the three standard names — a custom CA is used when chosen explicitly or as fallback." /></div>
      <p className="text-[11px] text-slate-500 mb-3">All intermediate keys are stored AES-256-GCM encrypted. The Root private key is handed to you once and shredded server-side — keep it offline.</p>

      <div className="text-sm font-bold mb-2">Step 3 · Generate</div>
      <Btn color="cyan" onClick={generate} disabled={busy} className="w-full py-2.5">
        {busy ? "Generating RSA PKI…" : result ? "✅ Generated — regenerate?" : `Generate PKI (${picked.length + (custom.trim() ? 1 : 0)} intermediate(s)) & Auto-Configure`}
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
