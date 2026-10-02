import { useEffect, useState } from "react";
import { apiJson, authHeaders, downloadBlob, errText } from "../api";
import { Btn, Card, DaysSelector, Field, inp, useToast } from "../ui";

const PRESETS = [
  {
    id: "server",
    title: "🌐 Web / TLS Server",
    purpose: "server",
    badge: "ServerAuth",
    days: "90",
    desc: "HTTPS websites, APIs, reverse proxies (Caddy, Traefik, Nginx, Ingress).",
    cnEx: "app.example.com",
    sansEx: "app.example.com, api.example.com, *.example.com",
  },
  {
    id: "mtls",
    title: "🔒 Mutual TLS / Client Auth",
    purpose: "client",
    badge: "ClientAuth / mTLS",
    days: "90",
    desc: "Zero-trust service-to-service auth, microservice APIs, developer/operator identities.",
    cnEx: "billing-service.internal",
    sansEx: "billing-service.internal, worker-01.internal",
  },
  {
    id: "wifi",
    title: "📶 WiFi / RADIUS (802.1X)",
    purpose: "wifi",
    badge: "EAP-TLS Enterprise",
    days: "365",
    desc: "WPA-Enterprise server certs for FreeRADIUS / Cisco ISE + client device certs.",
    cnEx: "radius.example.com",
    sansEx: "radius.example.com, radius-backup.example.com",
  },
  {
    id: "iot",
    title: "🤖 IoT & Fleet (MQTT / Edge)",
    purpose: "iot",
    badge: "Device Identity",
    days: "730",
    desc: "mTLS device certificates for MQTT brokers (EMQX, Mosquitto), edge gateways & sensors.",
    cnEx: "sensor-node-042.iot.internal",
    sansEx: "sensor-node-042.iot.internal",
  },
  {
    id: "k8s",
    title: "☸️ Kubernetes & Service Mesh",
    purpose: "k8s",
    badge: "etcd / Webhook / gRPC",
    days: "180",
    desc: "Validating webhook certs, etcd peer auth, Istio / Envoy proxies, and gRPC services.",
    cnEx: "webhook.cert-manager.svc",
    sansEx: "webhook.cert-manager.svc, webhook.cert-manager.svc.cluster.local",
  },
  {
    id: "vpn",
    title: "🛡️ VPN & Network Gateway",
    purpose: "vpn",
    badge: "Tunnel / Gateway",
    days: "365",
    desc: "OpenVPN, strongSwan IPsec, and WireGuard site-to-site gateway and client credentials.",
    cnEx: "vpn.corp.example.com",
    sansEx: "vpn.corp.example.com, gateway-01.internal",
  },
  {
    id: "codesign",
    title: "💻 Code Signing & Artifacts",
    purpose: "codesign",
    badge: "CodeSign / Scripts",
    days: "365",
    desc: "Signing internal PowerShell scripts, binaries, and container deployment manifests.",
    cnEx: "codesign.corp.internal",
    sansEx: "codesign.corp.internal",
  },
  {
    id: "custom",
    title: "🛠️ Custom / Advanced",
    purpose: "",
    badge: "Manual Config",
    days: "90",
    desc: "Specify Common Name, custom SANs, purpose, and CA routing manually.",
    cnEx: "service.custom.internal",
    sansEx: "service.custom.internal",
  },
];

const LEAF_PRESETS = [
  { label: "90 Days · ACME / Let's Encrypt default", value: "90" },
  { label: "30 Days · Short-lived mTLS / Dev", value: "30" },
  { label: "180 Days · 6 Months", value: "180" },
  { label: "1 Year (365 days)", value: "365" },
  { label: "2 Years (730 days)", value: "730" },
  { label: "825 Days · Maximum Allowed Leaf Limit", value: "825" },
];

const PURPOSE_CAS = {
  server: "int-server",
  client: "int-server",
  mtls: "int-server",
  wifi: "int-wifi",
  iot: "int-iot",
  k8s: "int-server",
  vpn: "int-server",
  codesign: "int-server",
  acme: "int-server",
};

const HELP = {
  preset: "Select your use case — automatically applies purpose routing, recommended validity period, and syntax examples.",
  cn: "Common Name: primary identity (e.g. app.example.com or service-name). Modern TLS clients verify SANs first, so keep CN aligned with primary SAN.",
  sans: "Comma-separated alternative names (DNS names, wildcards *.example.com, or IP addresses). Primary CN is auto-added if omitted.",
  days: "Leaf certificate validity period. Shorter (30–90d) reduces exposure window; internal PKIs allow up to 825 days.",
  ca: "Signing CA to issue this certificate. Auto matches the selected purpose with fallback to active CA.",
  purpose: "Routes the issuance: Server/mTLS/K8s/VPN → int-server, WiFi → int-wifi, IoT → int-iot, with automatic fallback.",
};

function Help({ text }) {
  return <p className="mt-1 text-[11px] leading-snug text-slate-400">{text}</p>;
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
  const [busy, setBusy] = useState(false);

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
    setCn(p.cnEx);
    setSans(p.sansEx);
    if (p.days) setDays(p.days);
  }

  // Client-side routing preview
  function preview() {
    if (!cas.length) return { text: "No Signing CA exists yet — setup required", bad: true };
    if (ca) return { text: `Signing with: ${ca} (Explicit manual override)` };
    const mapped = PURPOSE_CAS[purpose];
    if (mapped && cas.includes(mapped)) return { text: `Signing with: ${mapped} (Auto purpose: ${purpose || "auto"} → ${mapped})` };
    if (activeCA) return { text: `Signing with: ${activeCA} (Active CA default fallback)` };
    return { text: `Signing with: ${cas[0]} (First available intermediate)` };
  }
  const pv = preview();

  async function submit() {
    if (!cn.trim()) return toast("Common Name (CN) is required", true);
    setBusy(true);
    try {
      const { data } = await apiJson("/api/admin/generate-cert", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          commonName: cn.trim(),
          sans,
          days,
          ca: ca || undefined,
          purpose: purpose || undefined,
        }),
      });
      if (data.success) {
        setResult(data);
        toast(`Issued serial 0x${data.serial}${data.caSelection ? " via " + data.caSelection : ""}`);
        onChanged();
      } else if (data.code === "CA_NOT_AVAILABLE") {
        toast(
          <span>
            {errText(data, "Issuance failed")}{" "}
            <button className="underline font-bold" onClick={openWizard}>
              Open Setup Wizard
            </button>
          </span>,
          true
        );
      } else {
        toast(errText(data, "Issuance failed"), true);
      }
    } catch (e) {
      toast(e.message, true);
    }
    setBusy(false);
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100">Issue Leaf Certificate</h1>
          <p className="text-sm text-slate-400">
            Generates high-security private keys + CSR and signs them instantly via your Intermediate CA.
          </p>
        </div>
      </div>

      {!cas.length && (
        <div className="mb-4 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm flex items-center justify-between">
          <div>
            <strong className="text-amber-300">⚠️ No Signing CA exists yet.</strong>{" "}
            <span className="text-slate-300">Generate your Root + Intermediate CAs first to enable signing.</span>
          </div>
          <Btn color="cyan" className="text-xs" onClick={openWizard}>
            🧙 Launch Setup Wizard
          </Btn>
        </div>
      )}

      {/* 1. Purpose Presets */}
      <Card className="mb-4">
        <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-2.5">
          1 · Select Certificate Purpose & Use-Case Preset
        </div>
        <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
          {PRESETS.map((p) => {
            const isSelected = preset === p.id;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => pickPreset(p)}
                className={`rounded-xl border p-3.5 text-left transition-all cursor-pointer flex flex-col justify-between ${
                  isSelected
                    ? "border-cyan-500/80 bg-cyan-500/10 shadow-md shadow-cyan-500/10 ring-1 ring-cyan-500/30"
                    : "border-slate-800 hover:border-slate-600 bg-slate-950/40 hover:bg-slate-900/60"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="text-sm font-bold text-slate-100">{p.title}</span>
                  </div>
                  <div className="text-[11px] leading-relaxed text-slate-400">{p.desc}</div>
                </div>
                <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500">
                  <span className="mono bg-slate-900 px-1.5 py-0.5 rounded text-cyan-300/80">{p.badge}</span>
                  <span>{p.days}d default</span>
                </div>
              </button>
            );
          })}
        </div>
        <Help text={HELP.preset} />
      </Card>

      {/* 2. Certificate Details */}
      <Card className="max-w-3xl">
        <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-3">
          2 · Certificate Identity & Validity
        </div>

        <div className="grid grid-cols-1 gap-3.5 mb-3.5">
          <div>
            <Field label="Common Name (Primary Domain / FQDN / Service Identity)">
              <input
                value={cn}
                onChange={(e) => setCn(e.target.value)}
                placeholder={active.cnEx}
                className={inp}
              />
            </Field>
            <Help text={HELP.cn} />
          </div>

          <div>
            <Field label="Subject Alternative Names (SANs) · Comma-separated">
              <input
                value={sans}
                onChange={(e) => setSans(e.target.value)}
                placeholder={active.sansEx}
                className={inp}
              />
            </Field>
            <Help text={HELP.sans} />
          </div>

          <div>
            <Field label="Validity Duration">
              <DaysSelector
                value={days}
                onChange={setDays}
                presets={LEAF_PRESETS}
                min={1}
                max={825}
                placeholder="e.g. 90"
              />
            </Field>
            <Help text={HELP.days} />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 mb-4 pt-3 border-t border-slate-800/80">
          <div>
            <Field label="Signing CA Target">
              <select value={ca} onChange={(e) => setCa(e.target.value)} className={`${inp} cursor-pointer`}>
                <option value="">Auto (Recommended based on purpose)</option>
                {cas.map((c) => (
                  <option key={c} value={c}>
                    {c} {c === activeCA ? " · (Active Default)" : ""}
                  </option>
                ))}
              </select>
            </Field>
            <Help text={HELP.ca} />
          </div>

          <div>
            <Field label="Routing Purpose">
              <select
                value={purpose}
                onChange={(e) => setPurpose(e.target.value)}
                className={`${inp} cursor-pointer`}
              >
                <option value="">Auto / Default</option>
                <option value="server">🌐 Server / TLS / HTTPS</option>
                <option value="client">🔒 ClientAuth / mTLS (Zero-Trust)</option>
                <option value="wifi">📶 WiFi / RADIUS / 802.1X</option>
                <option value="iot">🤖 IoT / Device / MQTT</option>
                <option value="k8s">☸️ Kubernetes / Mesh / gRPC</option>
                <option value="vpn">🛡️ VPN & Network Gateway</option>
                <option value="codesign">💻 Code Signing & Artifacts</option>
                <option value="acme">⚡ ACME Protocol</option>
              </select>
            </Field>
            <Help text={HELP.purpose} />
          </div>
        </div>

        {/* Live routing badge */}
        <div
          className={`mb-4 flex items-center gap-2 rounded-lg border px-3.5 py-2.5 text-xs ${
            pv.bad
              ? "border-amber-500/40 bg-amber-500/10 text-amber-200"
              : "border-slate-800 bg-slate-950 text-slate-300"
          }`}
        >
          <span className="text-cyan-400">⚡</span>
          <span>{pv.text}</span>
        </div>

        <Btn color="cyan" onClick={submit} disabled={!cas.length || busy} className="w-full sm:w-auto px-6 py-2.5">
          {busy ? "Signing Certificate…" : "✨ Generate Keypair & Sign Certificate"}
        </Btn>
      </Card>

      {/* Result Card */}
      {result && (
        <Card className="mt-5 max-w-3xl border-emerald-500/50 bg-emerald-950/20 shadow-xl">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-lg text-emerald-400 flex items-center gap-2">
              <span>✅</span> Certificate Issued (Serial: <span className="mono text-white">0x{result.serial}</span>)
            </h3>
            <span className="text-xs rounded bg-emerald-500/20 text-emerald-300 px-2 py-0.5 font-semibold">
              Signed by {result.caName}
            </span>
          </div>
          <p className="text-xs text-slate-400 mb-3">
            Download your private key now. For zero-trust security, the private key is never saved on the server.
          </p>

          <div className="space-y-3">
            <div>
              <Field label="Private Key (PEM)">
                <textarea value={result.privateKey} rows={3} readOnly className={`${inp} mono text-xs bg-black/90`} />
              </Field>
            </div>
            <div>
              <Field label="Certificate Chain (Leaf + Intermediate + Root)">
                <textarea value={result.fullChain} rows={5} readOnly className={`${inp} mono text-xs bg-black/90`} />
              </Field>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap gap-2.5">
            <Btn
              color="emerald"
              className="text-xs flex items-center gap-1.5"
              onClick={() => downloadBlob(`${result.serial}-key.pem`, result.privateKey)}
            >
              <span>⬇</span> Download Private Key ({result.serial}-key.pem)
            </Btn>
            <Btn
              color="outline"
              className="text-xs flex items-center gap-1.5"
              onClick={() => downloadBlob(`${result.serial}-chain.pem`, result.fullChain)}
            >
              <span>⬇</span> Download Certificate Chain
            </Btn>
          </div>
        </Card>
      )}
    </div>
  );
}
