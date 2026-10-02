import { useEffect } from "react";
import { API_BASE } from "../api";
import { Btn, Card } from "../ui";

export default function Status({ status, latency, refresh }) {
  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const ok = status?.code === "READY";
  const crlExists = status?.crl?.exists;
  const dbLabel = status?.database || "—";
  const isJsonDb = dbLabel === "JSON file";

  const Cell = ({ label, children, warn, ok: cellOk }) => (
    <div className={`rounded-xl border p-4 ${
      warn ? "border-amber-500/30 bg-amber-500/5"
      : cellOk ? "border-emerald-500/30 bg-emerald-500/5"
      : "border-slate-800 bg-black"
    }`}>
      <div className="text-xs text-slate-400 mb-1">{label}</div>
      {children}
    </div>
  );

  return (
    <div>
      <h1 className="text-2xl font-extrabold">Connection Status</h1>
      <p className="text-sm text-slate-400 mb-5">
        Same <span className="mono">GET /api/v1/status</span> endpoint your clients use to check readiness.
      </p>

      <Card className="mb-4">
        <div className="flex flex-wrap items-center gap-3 mb-5">
          <Btn color="cyan" onClick={refresh}>↻ Refresh</Btn>
          <span className={`font-bold ${ok ? "text-emerald-400" : "text-amber-300"}`}>
            {status ? (ok ? "● READY" : `● ${status.code || "DOWN"}`) : "—"}
          </span>
          <span className="text-xs text-slate-400">
            {latency != null ? `${latency} ms · ${API_BASE}/api/v1/status` : ""}
          </span>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          {/* Signer */}
          <Cell label="Signer" ok={status?.status === "ready"}>
            <div className="font-bold text-cyan-300">{status?.status || "—"}</div>
          </Cell>

          {/* Active CA */}
          <Cell label="Active CA" ok={!!status?.activeCA}>
            <div className="font-bold text-cyan-300">{status?.activeCA || "none"}</div>
          </Cell>

          {/* Certs */}
          <Cell label="Certs valid / revoked">
            <div className="font-bold text-cyan-300">
              {status?.certificates ? `${status.certificates.valid} / ${status.certificates.revoked}` : "—"}
            </div>
          </Cell>

          {/* CRL */}
          <Cell label="CRL" warn={!crlExists} ok={crlExists}>
            {crlExists ? (
              <div className="font-bold text-emerald-300">✅ {status.crl.name}</div>
            ) : (
              <>
                <div className="font-bold text-amber-300">⚠️ Not yet generated</div>
                <p className="text-[11px] text-slate-400 mt-1">
                  CRL is generated automatically on next server restart, or when you revoke a cert, or when you activate a CA. No action required unless you need it immediately.
                </p>
              </>
            )}
          </Cell>

          {/* ACME */}
          <Cell label="ACME Directory">
            <div className="font-bold text-cyan-300 text-xs break-all">{status?.acme?.directory || "—"}</div>
          </Cell>

          {/* Database */}
          <Cell label="Database" warn={isJsonDb}>
            <div className={`font-bold ${isJsonDb ? "text-amber-300" : "text-emerald-300"}`}>
              {isJsonDb ? "📄 File storage" : "🐘 Managed database"}
            </div>
            {isJsonDb && (
              <p className="text-[11px] text-slate-400 mt-1">
                File storage is active. To switch to a managed database, contact your administrator. Data migrates automatically on first boot.
              </p>
            )}
          </Cell>
        </div>

        {/* Notices */}
        {isJsonDb && (
          <div className="mt-4 rounded-xl border border-amber-500/30 bg-amber-500/8 p-3.5">
            <div className="text-xs font-bold text-amber-400 mb-1">🗄️ Using file storage — suitable for single-instance use</div>
            <p className="text-[11px] text-slate-300">
              To upgrade to a <b>managed database</b>: contact your administrator to configure database storage.
              Your existing data (CAs, certs, tokens) migrates automatically on first boot.
            </p>
          </div>
        )}

        {!crlExists && ok && (
          <div className="mt-3 rounded-xl border border-amber-500/30 bg-amber-500/8 p-3.5">
            <div className="text-xs font-bold text-amber-400 mb-1">📋 CRL not yet generated — this is normal after a fresh install</div>
            <p className="text-[11px] text-slate-300">
              The CRL (Certificate Revocation List) is created the first time you <b>revoke a certificate</b>, <b>activate a CA</b>, or on server restart.
              Clients checking CRL URLs will get a 404 until then. This is harmless unless you need to distribute a CRL immediately — in that case, revoke any test cert to trigger generation.
            </p>
          </div>
        )}

        <label className="mt-5 block text-xs text-slate-400">Raw status JSON</label>
        <pre className="mt-1 overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs text-sky-300 mono custom-scroll">
          <code>{status ? JSON.stringify(status, null, 2) : "Press Refresh…"}</code>
        </pre>
      </Card>
    </div>
  );
}
