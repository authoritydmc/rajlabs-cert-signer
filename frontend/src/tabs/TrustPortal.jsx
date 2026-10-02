import { useEffect, useState } from "react";
import { API_BASE, api, apiJson } from "../api";
import { Btn, Card, useToast } from "../ui";

export default function TrustPortal({ onBackToLogin }) {
  const toast = useToast();
  const [summary, setSummary] = useState(null);
  const [origin, setOrigin] = useState("");
  const [activePlatform, setActivePlatform] = useState("windows");

  useEffect(() => {
    setOrigin(window.location.origin + API_BASE);
    (async () => {
      try {
        const { data } = await apiJson("/api/v1/trust-summary");
        if (data && data.success) setSummary(data);
      } catch {}
    })();
  }, []);

  function copyText(text, label = "Copied") {
    navigator.clipboard.writeText(text);
    toast(`${label} copied to clipboard!`);
  }

  const rootFp = summary?.rootCA?.fingerprintSha256 || "—";
  const orgName = summary?.orgName || "Enterprise PKI";

  const PLATFORMS = [
    { id: "windows", name: "🪟 Windows", icon: "🪟" },
    { id: "linux", name: "🐧 Linux", icon: "🐧" },
    { id: "apple", name: "🍎 macOS & iOS", icon: "🍎" },
    { id: "android", name: "🤖 Android", icon: "🤖" },
    { id: "java", name: "☕ Java / JVM", icon: "☕" },
    { id: "docker", name: "🐳 Docker / Containers", icon: "🐳" },
    { id: "runtimes", name: "🐍 CLI / Python / Node", icon: "🐍" },
  ];

  return (
    <div className="max-w-5xl mx-auto py-6 px-4 sm:px-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">🛡️</span>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100">{orgName} Public Trust Center</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Download Root and Intermediate CA certificates in all standard formats to establish trust on your devices.
          </p>
        </div>
        {onBackToLogin && (
          <Btn color="ghost" onClick={onBackToLogin} className="text-xs">
            ← Back to Admin Login
          </Btn>
        )}
      </div>

      {/* 1. Quick Download Matrix */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 mb-6">
        {/* Root CA Card */}
        <Card className="border-cyan-500/30 bg-slate-900/95 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm font-bold text-cyan-300 flex items-center gap-1.5">
                <span>🛡️</span> Root CA Certificate
              </span>
              <span className="rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-bold">
                Air-Gapped
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-3">
              Trust anchor for all certificates issued in this ecosystem. Install once per client machine.
            </p>

            <div className="rounded-lg bg-black/80 border border-slate-800 p-2.5 mb-3">
              <div className="text-[10px] text-slate-500 font-semibold mb-0.5">SHA-256 Fingerprint:</div>
              <div className="mono text-[11px] text-cyan-300 break-all select-all flex items-center justify-between gap-1">
                <span className="truncate">{rootFp}</span>
                {rootFp !== "—" && (
                  <button
                    onClick={() => copyText(rootFp, "SHA-256 Fingerprint")}
                    className="shrink-0 text-slate-400 hover:text-white"
                    title="Copy Fingerprint"
                  >
                    📋
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-1.5 pt-2 border-t border-slate-800">
            <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-1">Available Formats:</div>
            <div className="grid grid-cols-2 gap-1.5 text-xs">
              <a href={api("/certs/root-ca.crt?download=1")} className="w-full">
                <Btn color="outline" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>📄</span> .CRT (PEM)
                </Btn>
              </a>
              <a href={api("/certs/root-ca.der")} className="w-full">
                <Btn color="outline" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>💾</span> .DER (Binary)
                </Btn>
              </a>
              <a href={api("/certs/root-ca.cer")} className="w-full">
                <Btn color="outline" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>💾</span> .CER (Windows)
                </Btn>
              </a>
              <a href={api("/certs/root-ca.mobileconfig")} className="w-full">
                <Btn color="cyan" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>🍎</span> Apple Profile
                </Btn>
              </a>
            </div>
          </div>
        </Card>

        {/* Intermediate CA Card */}
        <Card className="border-slate-800 bg-slate-900/95 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm font-bold text-slate-200 flex items-center gap-1.5">
                <span>🏛️</span> Intermediate CA
              </span>
              <span className="rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 text-[10px] font-bold">
                Online Signer
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-3">
              Active signing authority ({summary?.activeCA || "int-server"}). Signs everyday TLS and device certificates.
            </p>

            <div className="rounded-lg bg-black/80 border border-slate-800 p-2.5 mb-3">
              <div className="text-[10px] text-slate-500 font-semibold mb-0.5">Active Signer:</div>
              <div className="mono text-xs text-slate-200 font-bold">{summary?.activeCA || "int-server"}</div>
            </div>
          </div>

          <div className="space-y-1.5 pt-2 border-t border-slate-800">
            <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-1">Available Formats:</div>
            <div className="grid grid-cols-2 gap-1.5 text-xs">
              <a href={api("/certs/intermediate-ca.crt?download=1")} className="w-full">
                <Btn color="outline" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>📄</span> .CRT (PEM)
                </Btn>
              </a>
              <a href={api("/certs/intermediate-ca.der")} className="w-full">
                <Btn color="outline" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>💾</span> .DER (Binary)
                </Btn>
              </a>
              <a href={api("/certs/intermediate-ca.cer")} className="w-full col-span-2">
                <Btn color="outline" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>💾</span> .CER (Windows Format)
                </Btn>
              </a>
            </div>
          </div>
        </Card>

        {/* Full Bundle & PKCS#7 Chain */}
        <Card className="border-slate-800 bg-slate-900/95 flex flex-col justify-between sm:col-span-2 lg:col-span-1">
          <div>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm font-bold text-slate-200 flex items-center gap-1.5">
                <span>📦</span> Complete Trust Chain
              </span>
              <span className="rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 text-[10px] font-bold">
                Bundled
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-3">
              Combined Root CA + Intermediate CA chain for servers, reverse proxies, and Group Policy deployment.
            </p>

            <div className="rounded-lg bg-black/80 border border-slate-800 p-2.5 mb-3">
              <div className="text-[10px] text-slate-500 font-semibold mb-0.5">Bundle Scope:</div>
              <div className="text-xs text-purple-300 font-medium">Root CA + Active Intermediate Chain</div>
            </div>
          </div>

          <div className="space-y-1.5 pt-2 border-t border-slate-800">
            <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-1">Available Formats:</div>
            <div className="grid grid-cols-2 gap-1.5 text-xs">
              <a href={api("/certs/ca-chain.crt?download=1")} className="w-full">
                <Btn color="cyan" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>📦</span> Full Chain (.crt)
                </Btn>
              </a>
              <a href={api("/certs/ca-chain.p7b")} className="w-full">
                <Btn color="outline" className="w-full py-1.5 text-xs flex items-center justify-center gap-1">
                  <span>💼</span> PKCS#7 (.p7b)
                </Btn>
              </a>
            </div>
          </div>
        </Card>
      </div>

      {/* 2. Automated 1-Command Installers */}
      <Card className="mb-6">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-bold text-base text-slate-100 flex items-center gap-2">
            <span>⚡</span> Automated 1-Command Trust Installation
          </h3>
        </div>

        <div className="space-y-3">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400 font-semibold mb-1">
              <span>🪟 Windows (Administrator PowerShell):</span>
              <button
                onClick={() => copyText(`irm ${origin}/install-trust-windows.ps1 | iex`)}
                className="text-cyan-400 hover:underline"
              >
                Copy Command
              </button>
            </div>
            <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-cyan-300 mono">
              <code>{`irm ${origin}/install-trust-windows.ps1 | iex`}</code>
            </pre>
          </div>

          <div>
            <div className="flex items-center justify-between text-xs text-slate-400 font-semibold mb-1">
              <span>🐧 Linux / macOS (Root Terminal):</span>
              <button
                onClick={() => copyText(`curl -fsSL ${origin}/install-trust-linux.sh | sudo bash`)}
                className="text-cyan-400 hover:underline"
              >
                Copy Command
              </button>
            </div>
            <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-cyan-300 mono">
              <code>{`curl -fsSL ${origin}/install-trust-linux.sh | sudo bash`}</code>
            </pre>
          </div>
        </div>
      </Card>

      {/* 3. Interactive Platform Guides */}
      <Card>
        <h3 className="font-bold text-base text-slate-100 mb-3 flex items-center gap-2">
          <span>📖</span> Manual Platform Installation Guides
        </h3>

        {/* Platform Tabs */}
        <div className="flex flex-wrap gap-1.5 border-b border-slate-800 pb-3 mb-4">
          {PLATFORMS.map((p) => (
            <button
              key={p.id}
              onClick={() => setActivePlatform(p.id)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition cursor-pointer ${
                activePlatform === p.id
                  ? "bg-cyan-500 text-slate-950 font-bold"
                  : "bg-slate-800 text-slate-300 hover:bg-slate-700"
              }`}
            >
              {p.name}
            </button>
          ))}
        </div>

        {/* Windows Guide */}
        {activePlatform === "windows" && (
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <h4 className="font-bold text-sm text-cyan-300">Installing on Windows</h4>
            <ol className="list-decimal list-inside space-y-1.5 pl-1">
              <li>
                Download <b>root-ca.cer</b> or <b>root-ca.crt</b>.
              </li>
              <li>
                Double-click the certificate file and click <b>Install Certificate…</b>
              </li>
              <li>
                Select <b>Local Machine</b> (requires Administrator) → Click Next.
              </li>
              <li>
                Choose <b>Place all certificates in the following store</b> → Click <b>Browse…</b>
              </li>
              <li>
                Select <b>Trusted Root Certification Authorities</b> → Click OK → Click Finish.
              </li>
            </ol>
            <p className="text-[11px] text-slate-500 mt-2">
              Tip: For automated deployments, use the PowerShell 1-liner above.
            </p>
          </div>
        )}

        {/* Linux Guide */}
        {activePlatform === "linux" && (
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <h4 className="font-bold text-sm text-cyan-300">Installing on Linux Distributions</h4>
            <div className="space-y-2">
              <div>
                <span className="font-semibold text-slate-200">Ubuntu / Debian:</span>
                <pre className="mt-1 rounded bg-black border border-slate-800 p-2 text-cyan-300 mono text-[11px]">
                  <code>{`sudo curl -fsSL "${origin}/certs/root-ca.crt" -o /usr/local/share/ca-certificates/rajlabs-root.crt\nsudo update-ca-certificates`}</code>
                </pre>
              </div>
              <div>
                <span className="font-semibold text-slate-200">RHEL / CentOS / Rocky / Fedora:</span>
                <pre className="mt-1 rounded bg-black border border-slate-800 p-2 text-cyan-300 mono text-[11px]">
                  <code>{`sudo curl -fsSL "${origin}/certs/root-ca.crt" -o /etc/pki/ca-trust/source/anchors/rajlabs-root.crt\nsudo update-ca-trust extract`}</code>
                </pre>
              </div>
              <div>
                <span className="font-semibold text-slate-200">Arch Linux:</span>
                <pre className="mt-1 rounded bg-black border border-slate-800 p-2 text-cyan-300 mono text-[11px]">
                  <code>{`sudo trust anchor --store "${origin}/certs/root-ca.crt"`}</code>
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Apple macOS / iOS Guide */}
        {activePlatform === "apple" && (
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <h4 className="font-bold text-sm text-cyan-300">Installing on macOS and iPhone / iPad</h4>
            <div className="space-y-2">
              <div>
                <span className="font-semibold text-slate-200">📱 iPhone / iPad (iOS 15+):</span>
                <p className="mt-0.5 text-slate-400">
                  1. Tap <a href={api("/certs/root-ca.mobileconfig")} className="text-cyan-400 underline font-semibold">Download Apple Profile (.mobileconfig)</a> in Safari.<br />
                  2. Open <b>Settings → Profile Downloaded</b> → Tap <b>Install</b>.<br />
                  3. Go to <b>Settings → General → About → Certificate Trust Settings</b> → Enable full trust for Root CA.
                </p>
              </div>
              <div>
                <span className="font-semibold text-slate-200">💻 macOS (Terminal CLI):</span>
                <pre className="mt-1 rounded bg-black border border-slate-800 p-2 text-cyan-300 mono text-[11px]">
                  <code>{`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root-ca.crt`}</code>
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Android Guide */}
        {activePlatform === "android" && (
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <h4 className="font-bold text-sm text-cyan-300">Installing on Android (Android 11+)</h4>
            <ol className="list-decimal list-inside space-y-1.5 pl-1">
              <li>
                Download <b>root-ca.crt</b> or <b>root-ca.cer</b> on your device.
              </li>
              <li>
                Open <b>Settings → Security & Privacy → More security settings → Encryption & credentials</b>.
              </li>
              <li>
                Tap <b>Install a certificate → CA certificate</b>.
              </li>
              <li>Tap <b>Install Anyway</b> and select the downloaded file.</li>
            </ol>
          </div>
        )}

        {/* Java Guide */}
        {activePlatform === "java" && (
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <h4 className="font-bold text-sm text-cyan-300">Java Virtual Machine (JVM cacerts)</h4>
            <p className="text-slate-400">Import the Root CA into the JDK truststore:</p>
            <pre className="rounded bg-black border border-slate-800 p-2.5 text-cyan-300 mono text-[11px]">
              <code>{`keytool -importcert -trustcacerts -alias "rajlabs-root-ca" \\\n  -file root-ca.crt -keystore "$JAVA_HOME/lib/security/cacerts" \\\n  -storepass changeit -noprompt`}</code>
            </pre>
          </div>
        )}

        {/* Docker Guide */}
        {activePlatform === "docker" && (
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <h4 className="font-bold text-sm text-cyan-300">Docker & Container Images</h4>
            <p className="text-slate-400">Inject the Root CA in your `Dockerfile`:</p>
            <pre className="rounded bg-black border border-slate-800 p-2.5 text-cyan-300 mono text-[11px]">
              <code>{`# Debian / Ubuntu based images\nADD ${origin}/certs/root-ca.crt /usr/local/share/ca-certificates/rajlabs-root.crt\nRUN update-ca-certificates\n\n# Alpine based images\nADD ${origin}/certs/root-ca.crt /usr/local/share/ca-certificates/rajlabs-root.crt\nRUN update-ca-certificates`}</code>
            </pre>
          </div>
        )}

        {/* CLI / Runtimes */}
        {activePlatform === "runtimes" && (
          <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
            <h4 className="font-bold text-sm text-cyan-300">Developer Tools & Runtime Environment Variables</h4>
            <pre className="rounded bg-black border border-slate-800 p-2.5 text-cyan-300 mono text-[11px]">
              <code>{`# Python / Requests / cURL\nexport REQUESTS_CA_BUNDLE=/path/to/root-ca.crt\nexport SSL_CERT_FILE=/path/to/root-ca.crt\nexport CURL_CA_BUNDLE=/path/to/root-ca.crt\n\n# Node.js\nexport NODE_EXTRA_CA_CERTS=/path/to/root-ca.crt\n\n# Git\ngit config --global http.sslCAInfo /path/to/root-ca.crt`}</code>
            </pre>
          </div>
        )}
      </Card>
    </div>
  );
}
