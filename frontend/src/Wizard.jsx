import { useState } from "react";
import { apiFetch, downloadBlob, errText } from "./api";
import { Btn, CountrySelect, DaysSelector, Field, Modal, inp, useToast } from "./ui";

// What each intermediate CA is for — shown in the wizard so admins pick knowingly.
const CA_TYPES = [
  {
    name: "int-server",
    title: "Web / TLS / ACME",
    icon: "🌐",
    for: "HTTPS websites & APIs, internal services, reverse proxies, ACME clients (Certbot, Traefik, Caddy).",
    clients: "Browsers, curl, Traefik, Nginx, Certbot",
    leafEx: "app.example.com (90 days)",
  },
  {
    name: "int-wifi",
    title: "WiFi / RADIUS (802.1X)",
    icon: "📶",
    for: "WPA-Enterprise networks: EAP-TLS server certificate for FreeRADIUS + client certificates for devices.",
    clients: "FreeRADIUS, WiFi APs, phones & laptops (EAP-TLS)",
    leafEx: "radius.example.com",
  },
  {
    name: "int-iot",
    title: "IoT / devices (MQTT)",
    icon: "🤖",
    for: "Mutual-TLS device identities for MQTT brokers and embedded fleets.",
    clients: "MQTT brokers, sensors, gateways",
    leafEx: "device-001.example.com",
  },
];

const ROOT_PRESETS = [
  { label: "20 Years (7,300d) · Recommended", value: "7300" },
  { label: "15 Years (5,475d)", value: "5475" },
  { label: "10 Years (3,650d)", value: "3650" },
  { label: "5 Years (1,825d)", value: "1825" },
  { label: "30 Years (10,950d)", value: "10950" },
];

const INT_PRESETS = [
  { label: "10 Years (3,650d) · Recommended", value: "3650" },
  { label: "5 Years (1,825d)", value: "1825" },
  { label: "3 Years (1,095d)", value: "1095" },
  { label: "2 Years (730d)", value: "730" },
  { label: "1 Year (365d)", value: "365" },
];

function Help({ text }) {
  return <p className="mt-1 text-[11px] leading-snug text-slate-400">{text}</p>;
}

export default function Wizard({ onClose, initialPassword }) {
  const toast = useToast();
  const [form, setForm] = useState({
    org: "Enterprise",
    country: "US",
    state: "California",
    city: "San Francisco",
    keySize: "4096",
    rootDays: "7300",
    intDays: "3650",
  });
  const [picked, setPicked] = useState(["int-server", "int-wifi", "int-iot"]);
  const [custom, setCustom] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const setVal = (k, v) => setForm((f) => ({ ...f, [k]: v }));
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
          orgName: form.org,
          country: form.country,
          state: form.state,
          city: form.city,
          keySize: form.keySize,
          rootDays: parseInt(form.rootDays, 10) || 7300,
          intDays: parseInt(form.intDays, 10) || 3650,
          intermediates: names.slice(0, 5),
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
      <p className="text-sm text-slate-400 mb-1">
        First-time setup — automatically creates your offline Root CA plus designated Signing CAs.
      </p>
      <p className="text-xs text-slate-500 mb-4">
        Workflow: <b>1.</b> Fill identity → <b>2.</b> Pick signing CAs → <b>3.</b> Generate & download Root key (server shreds its copy).
      </p>

      {/* Initial Admin Password notification */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 mb-5 shadow-inner">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-amber-400 mb-1.5">
          <span>🔐 Initial Admin Credentials</span>
        </div>
        <div className="flex items-center justify-between gap-2 rounded-lg bg-black/70 border border-amber-500/20 px-3 py-2 mono text-cyan-300 text-sm">
          <span className="truncate">{initialPassword || "Already set — use your ADMIN_PASSWORD (Coolify env)."}</span>
          {initialPassword && (
            <button
              className="shrink-0 rounded bg-slate-800 hover:bg-slate-700 px-2.5 py-1 text-xs text-slate-200 transition"
              onClick={() => {
                navigator.clipboard.writeText(initialPassword);
                toast("Admin password copied to clipboard");
              }}
            >
              Copy
            </button>
          )}
        </div>
      </div>

      {/* Step 1: Organization Identity */}
      <div className="border border-slate-800 rounded-xl bg-slate-950/40 p-4 mb-4">
        <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-2">
          <div className="text-sm font-bold text-slate-200">
            Step 1 · Organization Identity
            <span className="ml-2 font-normal text-xs text-slate-500 hidden sm:inline">(goes into certificate subjects)</span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 mb-3.5">
          <div>
            <Field label="Organization Name">
              <input value={form.org} onChange={set("org")} placeholder="Enterprise / Lab Name" className={inp} />
            </Field>
            <Help text="Appears as O= in every CA certificate (e.g. O=RajLabs)." />
          </div>

          <div>
            <Field label="Country">
              <CountrySelect value={form.country} onChange={(c) => setVal("country", c)} />
            </Field>
            <Help text="ISO 2-letter country code (C=)." />
          </div>

          <div>
            <Field label="State / Province">
              <input value={form.state} onChange={set("state")} placeholder="e.g. California" className={inp} />
            </Field>
            <Help text="Appears as ST= in certificate subjects." />
          </div>

          <div>
            <Field label="City / Locality">
              <input value={form.city} onChange={set("city")} placeholder="e.g. San Francisco" className={inp} />
            </Field>
            <Help text="Appears as L= in certificate subjects." />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 pt-2 border-t border-slate-800/50">
          <div>
            <Field label="Key Size / Strength">
              <select value={form.keySize} onChange={set("keySize")} className={`${inp} cursor-pointer`}>
                <option value="4096">4096-bit (Recommended)</option>
                <option value="3072">3072-bit</option>
                <option value="2048">2048-bit (Fastest)</option>
              </select>
            </Field>
            <Help text="4096-bit RSA is the gold standard for Root and Intermediate CAs." />
          </div>

          <div>
            <Field label="Root CA Validity">
              <DaysSelector
                value={form.rootDays}
                onChange={(d) => setVal("rootDays", d)}
                presets={ROOT_PRESETS}
                min={365}
                max={10950}
              />
            </Field>
            <Help text="Root CA stays offline for years. 20y is typical." />
          </div>

          <div>
            <Field label="Intermediate CA Validity">
              <DaysSelector
                value={form.intDays}
                onChange={(d) => setVal("intDays", d)}
                presets={INT_PRESETS}
                min={365}
                max={5475}
              />
            </Field>
            <Help text="Signing CAs handle everyday workloads. 10y is standard." />
          </div>
        </div>
      </div>

      {/* Step 2: Intermediate CAs */}
      <div className="border border-slate-800 rounded-xl bg-slate-950/40 p-4 mb-4">
        <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-2">
          <div className="text-sm font-bold text-slate-200">
            Step 2 · Which Signing CAs do you need?
            <span className="ml-2 font-normal text-xs text-slate-500 hidden sm:inline">(select 1 to 3 CAs)</span>
          </div>
        </div>

        <div className="grid gap-2.5 sm:grid-cols-3 mb-3">
          {CA_TYPES.map((c) => {
            const isSelected = picked.includes(c.name);
            return (
              <label
                key={c.name}
                className={`rounded-xl border p-3 cursor-pointer transition-all ${
                  isSelected
                    ? "border-cyan-500/80 bg-cyan-500/10 shadow-sm shadow-cyan-500/10"
                    : "border-slate-800 hover:border-slate-600 bg-slate-900/50"
                }`}
              >
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggle(c.name)}
                    className="accent-cyan-500 h-4 w-4 rounded"
                  />
                  <span className="mono text-sm font-bold text-slate-100">{c.name}</span>
                </div>
                <div className="mt-1.5 text-xs font-semibold text-cyan-300 flex items-center gap-1">
                  <span>{c.icon}</span> <span>{c.title}</span>
                </div>
                <div className="mt-1 text-[11px] leading-relaxed text-slate-300">{c.for}</div>
                <div className="mt-2 text-[10px] text-slate-500">Clients: {c.clients}</div>
                <div className="mt-0.5 text-[10px] text-slate-500">
                  Example: <span className="mono text-slate-400">{c.leafEx}</span>
                </div>
              </label>
            );
          })}
        </div>

        <div className="mt-2">
          <Field label="Custom Intermediate CA (optional)">
            <input
              value={custom}
              onChange={(e) => setCustom(e.target.value)}
              placeholder="e.g. int-vpn or int-k8s"
              className={inp}
            />
          </Field>
          <Help text="Custom CA names will be generated alongside the standard signing CAs." />
        </div>

        <p className="mt-3 text-[11px] text-slate-500">
          🔒 Intermediate keys are stored encrypted (AES-256-GCM). The Root private key is displayed for download once and securely shredded from the server.
        </p>
      </div>

      {/* Step 3: Generate */}
      <div className="pt-2">
        <div className="text-sm font-bold text-slate-200 mb-2">Step 3 · Generate & Initialize PKI</div>
        <Btn color="cyan" onClick={generate} disabled={busy} className="w-full py-3 text-base">
          {busy ? (
            <span className="flex items-center justify-center gap-2">
              <span className="inline-block animate-spin">🌀</span> Generating RSA PKI Infrastructure…
            </span>
          ) : result ? (
            "✅ PKI Generated — Regenerate?"
          ) : (
            `🚀 Generate PKI (${picked.length + (custom.trim() ? 1 : 0)} Intermediate${
              picked.length + (custom.trim() ? 1 : 0) > 1 ? "s" : ""
            }) & Configure`
          )}
        </Btn>
      </div>

      {result && (
        <div className="mt-4 rounded-xl border border-emerald-500/40 bg-emerald-950/30 p-4">
          <h4 className="font-bold text-emerald-400 mb-1 flex items-center gap-1.5">
            <span>✅</span> PKI Generated Successfully — Download Root Key Now
          </h4>
          <p className="text-xs text-red-300 mb-3">
            ⚠️ <b>Important:</b> Download and store <span className="mono">root-ca.key.pem</span> in a secure offline vault. The server does not retain a copy.
          </p>
          <div className="flex flex-col gap-2">
            <button
              className="rounded-lg bg-red-600 hover:bg-red-500 px-3.5 py-2.5 text-sm font-bold text-white shadow-md shadow-red-600/20 transition text-left flex items-center justify-between"
              onClick={() => downloadBlob("root-ca.key.pem", result.rootKeyPem)}
            >
              <span>🛡️ Download ROOT Private Key (keep offline!)</span>
              <span className="text-xs bg-red-800/80 px-2 py-0.5 rounded">root-ca.key.pem</span>
            </button>
            <button
              className="rounded-lg border border-slate-700 hover:border-slate-500 bg-slate-900 px-3.5 py-2 text-sm text-slate-200 transition text-left flex items-center justify-between"
              onClick={() => downloadBlob("root-ca.cert.pem", result.rootCertPem)}
            >
              <span>📄 Download Root CA Certificate</span>
              <span className="text-xs text-slate-400">root-ca.cert.pem</span>
            </button>
            {result.intermediates.map((ca) => (
              <button
                key={ca.name}
                className="rounded-lg border border-slate-700 hover:border-slate-500 bg-slate-900 px-3.5 py-2 text-sm text-slate-200 transition text-left flex items-center justify-between"
                onClick={() => downloadBlob(`${ca.name}-chain.crt`, ca.chainPem)}
              >
                <span>📦 Download {ca.name} Certificate Chain</span>
                <span className="text-xs text-slate-400">{ca.name}-chain.crt</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="mt-5 flex justify-end border-t border-slate-800 pt-3">
        <Btn color="cyan" onClick={finish}>
          Proceed to Dashboard →
        </Btn>
      </div>
    </Modal>
  );
}
