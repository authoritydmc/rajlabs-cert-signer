import { useEffect } from "react";
import { API_BASE } from "../api";
import { Btn, Card } from "../ui";

export default function Status({ status, latency, refresh }) {
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const ok = status?.code === "READY";
  const cell = (label, value, mono = false) => (
    <div className="rounded-xl border border-slate-800 bg-black p-4">
      <div className="text-xs text-slate-400">{label}</div>
      <div className={`font-bold ${mono ? "text-xs break-all text-cyan-300" : "text-cyan-300"}`}>{value}</div>
    </div>
  );
  return (
    <div>
      <h1 className="text-2xl font-extrabold">Connection Status</h1>
      <p className="text-sm text-slate-400 mb-5">
        Same <span className="mono">GET /api/v1/status</span> contract your backend.rajlabs.in admin tab polls.
      </p>
      <Card className="mb-4">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <Btn color="cyan" onClick={refresh}>↻ Refresh</Btn>
          <span className="font-bold">{status ? (ok ? "● READY" : `● ${status.code || "DOWN"}`) : "—"}</span>
          <span className="text-xs text-slate-400">
            {latency != null ? `${latency} ms · ${API_BASE}/api/v1/status` : ""}
          </span>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          {cell("Signer", status?.status || "—")}
          {cell("Active CA", status?.activeCA || "none")}
          {cell("Certs valid/revoked", status?.certificates ? `${status.certificates.valid}/${status.certificates.revoked}` : "—")}
          {cell("CRL", status?.crl ? (status.crl.exists ? `✅ ${status.crl.name}` : "❌ missing") : "—")}
          {cell("ACME", status?.acme?.directory || "—", true)}
          {cell("Database", status?.database || "—")}
        </div>
        <label className="mt-4 block text-xs text-slate-400">Raw status JSON</label>
        <pre className="mt-1 overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-sky-300 mono">
          <code>{status ? JSON.stringify(status, null, 2) : "Press Refresh…"}</code>
        </pre>
      </Card>
    </div>
  );
}
