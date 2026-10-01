import { useEffect, useState } from "react";
import { API_BASE, api } from "../api";
import { Btn, Card } from "../ui";

export default function Overview({ status, refresh }) {
  const [origin, setOrigin] = useState("");
  useEffect(() => {
    setOrigin(window.location.origin + API_BASE);
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-extrabold">PKI Dashboard & Trust Downloads</h1>
      <p className="text-sm text-slate-400 mb-5">Authority health and client trust bundles.</p>
      <div className="grid gap-3 sm:grid-cols-3 mb-5">
        <Card><div className="text-xs text-slate-400">Active signer</div>
          <div className="mt-1 text-xl font-bold text-cyan-400">{status?.activeCA || "None — import one!"}</div></Card>
        <Card><div className="text-xs text-slate-400">Certificates issued</div>
          <div className="mt-1 text-xl font-bold text-cyan-400">{status?.certificates?.total ?? 0}</div></Card>
        <Card><div className="text-xs text-slate-400">Root CA</div>
          <div className="mt-1 text-xl font-bold text-emerald-400">Air-Gapped 🛡️</div></Card>
      </div>

      {status && status.code !== "READY" && (
        <div className="mb-5 rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm">
          <strong className="text-red-300">⚠️ {status.message}</strong>
          <span className="text-slate-400"> Go to Intermediate CAs → Import / Generate.</span>
        </div>
      )}

      <Card className="border-cyan-500/30 mb-5">
        <h2 className="font-bold text-cyan-300 mb-1">📥 Trust downloads</h2>
        <div className="flex flex-wrap gap-2 mt-3">
          <a href={api("/certs/root-ca.crt?download=1")}><Btn color="outline">📄 Root CA</Btn></a>
          <a href={api("/certs/intermediate-ca.crt?download=1")}><Btn color="outline">📄 Intermediate CA</Btn></a>
          <a href={api("/certs/ca-chain.crt?download=1")}><Btn color="cyan">📦 Full chain</Btn></a>
        </div>
      </Card>

      <Card>
        <h3 className="font-bold mb-3">💻 1-command client trust install</h3>
        <label className="text-xs text-slate-400">Windows (admin PowerShell)</label>
        <pre className="mb-3 overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-sky-300 mono">
          <code>{`irm ${origin}/install-trust-windows.ps1 | iex`}</code>
        </pre>
        <label className="text-xs text-slate-400">Linux</label>
        <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-sky-300 mono">
          <code>{`curl -fsSL ${origin}/install-trust-linux.sh | sudo bash`}</code>
        </pre>
      </Card>
    </div>
  );
}
