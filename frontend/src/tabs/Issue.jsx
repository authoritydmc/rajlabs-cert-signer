import { useEffect, useState } from "react";
import { apiJson, authHeaders, downloadBlob, errText } from "../api";
import { Btn, Card, Field, inp, useToast } from "../ui";

const PRESETS = [
  {
    id: "server", title: "🌐 Web / TLS server", purpose: "server",
    desc: "HTTPS APIs, websites, internal services, reverse proxies.",
    cnEx: "app.example.com", sansEx: "app.example.com, api.example.com",
  },
  {
    id: "wifi", title: "📶 WiFi / RADIUS (802.1X)", purpose: "wifi",
    desc: "EAP-TLS server cert for WPA-Enterprise (FreeRADIUS) and client certs.",
    cnEx: "radius.example.com", sansEx: "radius.example.com",
  },
  {
    id: "iot", title: "🤖 IoT / device (MQTT)", purpose: "iot",
    desc: "mTLS device identities for MQTT brokers and embedded fleets.",
    cnEx: "device-001.example.com", sansEx: "device-001.example.com",
  },
  {
    id: "custom", title: "🛠️ Custom", purpose: "",
    desc: "Pick CA and purpose yourself.",
    cnEx: "service.example.com", sansEx: "service.example.com",
  },
];

const PURPOSE_CAS = { server: "int-server", wifi: "int-wifi", iot: "int-iot", acme: "int-server" };

const HELP = {
  preset: "Pick what the certificate is for — it fills the purpose (which routes to the right Signing CA) and shows example values.",
  cn: "Common Name: the primary identity, usually a domain (app.example.com). Browsers check SANs first, so keep CN equal to the first SAN.",
  sans: "Comma-separated extra identities: more DNS names (and IPs are accepted). The Common Name is added automatically if missing.",
  days: "How long the leaf certificate stays valid. Shorter (30–90d) is safer; internal PKI allows up to 825d. (CA lifetimes are separate.)",
  ca: "Which Signing CA signs this. Auto chooses from purpose → active CA. Only CAs that actually exist are listed.",
  purpose: "Routes the request: server→int-server, wifi/radius→int-wifi, iot/device→int-iot — then falls back to the active CA.",
};

function Help({ text }) {
  return <p className="mt-1 text-[11px] leading-snug text-slate-500">{text}</p>;
}

export default function Issue({ onChanged, openWizard }) {
  const toast = useToast();
  const [cas, setCas] = useState([]);
  const [activeCA, setActiveCA] = useState("");
  const [preset, setPreset] = useState("server");
  const [cn, setCn] = useState("");
  const [sans, setSans] = useState("");
  const [days, setDays] = useState("90");
  const [ca, setCa] = useState("");
  const [purpose, setPurpose] = useState("server");
  const [result, setResult] = useState(null);

  const active = PRESETS.find((p) => p.id === preset) || PRESETS[0];

  useEffect(() => {
    (async () => {
      const { data } = await apiJson("/api/admin/intermediate-cas", { headers: authHeaders() });
      const list = Array.isArray(data) ? data : [];
      setCas(list.map((c) => c.name));
      setActiveCA((list.find((c) => c.isActive) || {}).name || "");
      const { data: prof } = await apiJson("/api/admin/profile", { headers: authHeaders() }).catch(() => ({ data: {} }));
      if (prof?.domainSuffix) {
        setCn((v) => v || `app.${prof.domainSuffix}`);
        setSans((v) => v || `app.${prof.domainSuffix}, api.${prof.domainSuffix}`);
      }
      if (prof?.defaultDays) setDays(String(prof.defaultDays));
    })();
  }, []);

  function pickPreset(p) {
    setPreset(p.id);
    setPurpose(p.purpose);
    setCn((v) => v || p.cnEx);
    setSans((v) => v || p.sansEx);
  }

  // Client-side routing preview (server is authoritative, echoes caSelection).
  function preview() {
    if (!cas.length) return { text: "No Signing CA exists yet", bad: true };
    if (ca) return { text: `Will sign with ${ca} (explicit choice)` };
    const mapped = PURPOSE_CAS[purpose];
    if (mapped && cas.includes(mapped)) return { text: `Will sign with ${mapped} (purpose ${purpose || "auto"} → ${mapped})` };
    if (activeCA) return { text: `Will sign with ${activeCA} (active CA fallback)` };
    return { text: `Will sign with ${cas[0]} (first available)` };
  }
  const pv = preview();

  async function submit() {
    if (!cn.trim()) return toast("Common Name is required", true);
    const { data } = await apiJson("/api/admin/generate-cert", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ commonName: cn.trim(), sans, days, ca: ca || undefined, purpose: purpose || undefined }),
    });
    if (data.success) {
      setResult(data);
      toast(`Issued serial ${data.serial}${data.caSelection ? " via " + data.caSelection : ""}`);
      onChanged();
    } else if (data.code === "CA_NOT_AVAILABLE") {
      toast(<span>{errText(data, "Issuance failed")} <button className="underline" onClick={openWizard}>Open Setup Wizard</button></span>, true);
    } else toast(errText(data, "Issuance failed"), true);
  }

  return (
    <div>
      <h1 className="text-2xl font-extrabold">Issue Leaf Certificate</h1>
      <p className="text-sm text-slate-400 mb-4">Generates a fresh private key + CSR and signs it in one step. The key is shown once — save it.</p>

      {!cas.length && (
        <div className="mb-4 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm">
          <strong className="text-amber-300">⚠️ No Signing CA exists yet.</strong>{" "}
          <span className="text-slate-300">Generate Root + intermediates first:</span>{" "}
          <button className="underline font-semibold" onClick={openWizard}>🧙 Open Setup Wizard</button>
        </div>
      )}

      <Card className="mb-4">
        <div className="text-xs font-semibold text-slate-300 mb-2">1 · What is this certificate for?</div>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {PRESETS.map((p) => (
            <button key={p.id} onClick={() => pickPreset(p)}
              className={`rounded-xl border p-3 text-left transition ${preset === p.id ? "border-cyan-500 bg-cyan-500/10" : "border-slate-700 hover:border-slate-500"}`}>
              <div className="text-sm font-bold">{p.title}</div>
              <div className="mt-1 text-[11px] text-slate-400">{p.desc}</div>
            </button>
          ))}
        </div>
        <Help text={HELP.preset} />
      </Card>

      <Card className="max-w-2xl">
        <div className="text-xs font-semibold text-slate-300 mb-3">2 · Certificate details</div>
        <div className="mb-3">
          <Field label="Common Name (CN)"><input value={cn} onChange={(e) => setCn(e.target.value)} placeholder={active.cnEx} className={inp} /></Field>
          <Help text={HELP.cn} />
        </div>
        <div className="mb-3">
          <Field label="Subject Alternative Names (SANs)"><input value={sans} onChange={(e) => setSans(e.target.value)} placeholder={active.sansEx} className={inp} /></Field>
          <Help text={HELP.sans} />
        </div>
        <div className="mb-3">
          <Field label="Validity (days)"><input value={days} onChange={(e) => setDays(e.target.value)} type="number" min="1" max="825" className={inp} /></Field>
          <Help text={HELP.days} />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
          <div>
            <Field label="Signing CA">
              <select value={ca} onChange={(e) => setCa(e.target.value)} className={inp}>
                <option value="">Auto (recommended)</option>
                {cas.map((c) => <option key={c} value={c}>{c}{c === activeCA ? " · active" : ""}</option>)}
              </select>
            </Field>
            <Help text={HELP.ca} />
          </div>
          <div>
            <Field label="Purpose">
              <select value={purpose} onChange={(e) => setPurpose(e.target.value)} className={inp}>
                <option value="">Auto</option>
                <option value="server">server / web / TLS</option>
                <option value="wifi">wifi / RADIUS / 802.1X</option>
                <option value="iot">iot / device / MQTT</option>
                <option value="acme">acme</option>
              </select>
            </Field>
            <Help text={HELP.purpose} />
          </div>
        </div>
        <div className={`mb-3 rounded-lg border px-3 py-2 text-xs ${pv.bad ? "border-amber-500/40 bg-amber-500/10 text-amber-200" : "border-slate-700 bg-black text-slate-300"}`}>
          🔍 {pv.text}
        </div>
        <Btn color="cyan" onClick={submit} disabled={!cas.length}>Generate & Sign</Btn>
      </Card>

      {result && (
        <Card className="mt-4 max-w-2xl border-emerald-500/40">
          <h3 className="font-bold text-emerald-400 mb-1">✅ Issued (serial {result.serial})</h3>
          <p className="text-xs text-slate-400 mb-2">Signed by {result.caName}{result.caSelection ? ` (${result.caSelection})` : ""}. Save the private key now — it is never stored.</p>
          <Field label="Private key"><textarea value={result.privateKey} rows={3} readOnly className={`${inp} mono text-xs`} /></Field>
          <div className="mt-2"><Field label="Full chain (leaf + intermediate + root)"><textarea value={result.fullChain} rows={5} readOnly className={`${inp} mono text-xs`} /></Field></div>
          <div className="mt-2 flex gap-2">
            <Btn color="outline" className="text-xs" onClick={() => downloadBlob(`${result.serial}-key.pem`, result.privateKey)}>⬇ Key</Btn>
            <Btn color="outline" className="text-xs" onClick={() => downloadBlob(`${result.serial}-chain.pem`, result.fullChain)}>⬇ Chain</Btn>
          </div>
        </Card>
      )}
    </div>
  );
}
