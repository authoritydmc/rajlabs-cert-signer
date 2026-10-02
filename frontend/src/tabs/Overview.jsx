import { useEffect, useState } from "react";
import { API_BASE, api } from "../api";
import { Btn, Card } from "../ui";

export default function Overview({ status, refresh, openWizard }) {
  const [origin, setOrigin] = useState("");
  useEffect(() => {
    setOrigin(window.location.origin + API_BASE);
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const hasActiveCA = Boolean(status?.activeCA && status?.code === "READY");

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100">PKI Dashboard & Trust Downloads</h1>
          <p className="text-sm text-slate-400">Authority health, active signer status, and client trust bundles.</p>
        </div>
        {!hasActiveCA && (
          <Btn color="cyan" onClick={openWizard} className="text-xs">
            🧙 Launch Setup Wizard
          </Btn>
        )}
      </div>

      <div className="grid gap-3 sm:grid-cols-3 mb-5">
        <Card>
          <div className="text-xs font-semibold text-slate-400">Active Signer CA</div>
          <div className="mt-1.5 flex items-center gap-2">
            {hasActiveCA ? (
              <span className="text-xl font-bold text-cyan-400 flex items-center gap-1.5">
                <span className="inline-block h-2.5 w-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
                {status.activeCA}
              </span>
            ) : (
              <span className="text-base font-bold text-amber-400 flex items-center gap-1.5">
                <span>⚠️</span> No Active Signer
              </span>
            )}
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            {hasActiveCA ? "Signing online & accepting CSRs" : "Generate or import a Signing CA to begin"}
          </div>
        </Card>

        <Card>
          <div className="text-xs font-semibold text-slate-400">Certificates Issued</div>
          <div className="mt-1.5 text-xl font-bold text-cyan-400">
            {status?.certificates?.total ?? 0}
          </div>
          <div className="mt-1 text-[11px] text-slate-500">
            {status?.certificates?.revoked ?? 0} revoked · {status?.certificates?.valid ?? 0} active
          </div>
        </Card>

        <Card>
          <div className="text-xs font-semibold text-slate-400">Root CA Storage</div>
          <div className="mt-1.5 text-xl font-bold text-emerald-400 flex items-center gap-1.5">
            <span>🛡️</span> Air-Gapped / Offline
          </div>
          <div className="mt-1 text-[11px] text-slate-500">Private key shredded from server</div>
        </Card>
      </div>

      {status && status.code !== "READY" && (
        <div className="mb-5 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <strong className="text-amber-300">⚠️ {status.message || "No Intermediate CA configured."}</strong>
            <p className="text-xs text-slate-300 mt-0.5">
              The signer requires at least one active intermediate CA (e.g. <span className="mono">int-server</span>) to sign certificates.
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <Btn color="cyan" className="text-xs" onClick={openWizard}>
              🧙 Open Wizard
            </Btn>
          </div>
        </div>
      )}

      <Card className="border-cyan-500/30 mb-5">
        <h2 className="font-bold text-cyan-300 mb-1">📥 Client Trust Downloads</h2>
        <p className="text-xs text-slate-400 mb-3">Distribute root and intermediate certificate chains to client machines.</p>
        <div className="flex flex-wrap gap-2.5">
          <a href={api("/certs/root-ca.crt?download=1")}>
            <Btn color="outline" className="text-xs">📄 Root CA (.crt)</Btn>
          </a>
          <a href={api("/certs/intermediate-ca.crt?download=1")}>
            <Btn color="outline" className="text-xs">📄 Intermediate CA (.crt)</Btn>
          </a>
          <a href={api("/certs/ca-chain.crt?download=1")}>
            <Btn color="cyan" className="text-xs">📦 Full Chain (.crt)</Btn>
          </a>
        </div>
      </Card>

      <Card>
        <h3 className="font-bold mb-3 text-slate-200">💻 1-Command Automated Trust Install</h3>
        <label className="text-xs text-slate-400 font-semibold block mb-1">Windows (Administrator PowerShell)</label>
        <pre className="mb-4 overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-cyan-300 mono">
          <code>{`irm ${origin}/install-trust-windows.ps1 | iex`}</code>
        </pre>
        <label className="text-xs text-slate-400 font-semibold block mb-1">Linux / macOS (Terminal)</label>
        <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-cyan-300 mono">
          <code>{`curl -fsSL ${origin}/install-trust-linux.sh | sudo bash`}</code>
        </pre>
      </Card>
    </div>
  );
}
