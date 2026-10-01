import { useEffect, useState } from "react";
import { apiJson, authHeaders, downloadBlob, errText } from "../api";
import { Btn, Card, Empty, inp, useToast } from "../ui";

const LABELS = {
  "auth.login_ok": "✅ login", "auth.login_failed": "❌ login failed",
  "pki.onboarded": "🎉 PKI onboarded",
  "cert.issued": "📜 issued", "cert.renewed": "🔄 renewed", "cert.downloaded": "⬇ downloaded",
  "cert.revoked": "🚫 revoked", "cert.bulk_revoked": "🚫 bulk revoke",
  "token.created": "🔑 token created", "token.revoked": "🔑 token revoked",
  "token.restored": "🔑 token restored", "token.deleted": "🔑 token deleted", "token.bulk": "🔑 token bulk",
  "ca.imported": "🏛️ CA imported", "ca.activated": "🏛️ CA activated", "ca.deleted": "🏛️ CA deleted",
};

function details(e) {
  const d = e.details || {};
  const parts = [];
  if (d.user) parts.push(`user=${d.user}`);
  if (d.oldSerial && d.newSerial) parts.push(`0x${d.oldSerial} → 0x${d.newSerial}`);
  else if (d.serial) parts.push(`0x${d.serial}`);
  if (d.newSerial && !d.oldSerial) parts.push(`new=0x${d.newSerial}`);
  if (d.kind) parts.push(`kind=${d.kind}`);
  if (d.cn) parts.push(`cn=${d.cn}`);
  if (d.via) parts.push(`via=${d.via}`);
  if (d.name) parts.push(`name=${d.name}`);
  if (d.reason) parts.push(`reason=${d.reason}`);
  if (d.action) parts.push(`action=${d.action}`);
  if (d.affected !== undefined) parts.push(`affected=${d.affected}`);
  if (d.certsIssued !== undefined) parts.push(`certs=${d.certsIssued}`);
  return parts.join(" · ") || "—";
}

export default function Audit() {
  const toast = useToast();
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState({});
  const [events, setEvents] = useState([]);
  const [ev, setEv] = useState("");
  const [q, setQ] = useState("");
  const [limit, setLimit] = useState("100");
  const [offset, setOffset] = useState(0);

  async function fetchPage(append, off) {
    const params = new URLSearchParams({ limit, offset: String(off) });
    if (ev) params.set("event", ev);
    if (q.trim()) params.set("q", q.trim());
    const { data } = await apiJson("/api/admin/audit?" + params.toString(), { headers: authHeaders() });
    if (!data.success) {
      toast(errText(data, "Audit load failed"), true);
      return;
    }
    setTotal(data.total);
    setCounts(data.eventCounts || {});
    setEntries((prev) => (append ? [...prev, ...data.entries] : data.entries));
  }
  async function reload() {
    setOffset(0);
    await fetchPage(false, 0);
  }
  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ev, limit]);

  useEffect(() => {
    setEvents(Object.keys(counts).sort());
  }, [counts]);

  async function exportJson() {
    const params = new URLSearchParams({ limit: "500", offset: "0" });
    if (ev) params.set("event", ev);
    if (q.trim()) params.set("q", q.trim());
    const { data } = await apiJson("/api/admin/audit?" + params.toString(), { headers: authHeaders() });
    if (!data.success) return toast(errText(data, "Export failed"), true);
    downloadBlob(`audit-export-${new Date().toISOString().slice(0, 10)}.json`,
      JSON.stringify(data.entries, null, 2), "application/json");
    toast(`Exported ${data.entries.length} audit entries.`);
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div>
          <h1 className="text-2xl font-extrabold">Audit Logs</h1>
          <p className="text-sm text-slate-400">Every login, issuance, renewal, download, revocation, token & CA change. Newest first.</p>
        </div>
        <div className="flex gap-2">
          <Btn color="outline" onClick={exportJson}>⬇ Export JSON</Btn>
          <Btn color="cyan" onClick={reload}>↻ Refresh</Btn>
        </div>
      </div>
      <Card className="mb-4">
        <div className="grid gap-3 sm:grid-cols-4">
          <label className="block text-xs text-slate-400">Event
            <select value={ev} onChange={(e) => setEv(e.target.value)} className={`${inp} mt-1`}>
              <option value="">All events</option>
              {events.map((e) => <option key={e} value={e}>{LABELS[e] || e} ({counts[e]})</option>)}
            </select></label>
          <label className="block text-xs text-slate-400 sm:col-span-2">Search
            <input value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && reload()}
              placeholder="e.g. radius, revoked, 0x1f3…" className={`${inp} mt-1`} /></label>
          <label className="block text-xs text-slate-400">Rows
            <select value={limit} onChange={(e) => setLimit(e.target.value)} className={`${inp} mt-1`}>
              <option>50</option><option>100</option><option>250</option><option>500</option>
            </select></label>
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5 text-[11px]">
          {events.map((e) => (
            <button key={e} onClick={() => setEv(e)}
              className="rounded-full border border-slate-700 px-2 py-0.5 text-slate-300 hover:border-cyan-500">
              {LABELS[e] || e} · {counts[e]}
            </button>
          ))}
        </div>
      </Card>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead><tr className="text-slate-400">
              <th className="p-2">Time</th><th className="p-2">Event</th><th className="p-2">Actor</th>
              <th className="p-2">IP</th><th className="p-2">Details</th>
            </tr></thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={i} className="border-t border-slate-800">
                  <td className="p-2 text-xs text-slate-400 whitespace-nowrap">{e.ts ? new Date(e.ts).toLocaleString() : "-"}</td>
                  <td className="p-2 text-xs whitespace-nowrap">{LABELS[e.event] || e.event}</td>
                  <td className="p-2 text-xs">{e.actor || "—"}</td>
                  <td className="p-2 text-xs text-slate-500 mono">{e.ip || "—"}</td>
                  <td className="p-2 text-xs text-slate-300">{details(e)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!entries.length && <Empty>No audit entries yet.</Empty>}
        </div>
        <div className="mt-3 flex items-center justify-between">
          <span className="text-xs text-slate-500">showing {entries.length} of {total}</span>
          {entries.length < total && (
            <Btn color="outline" className="text-xs" onClick={async () => {
              const off = offset + parseInt(limit, 10);
              setOffset(off);
              const params = new URLSearchParams({ limit, offset: String(off) });
              if (ev) params.set("event", ev);
              if (q.trim()) params.set("q", q.trim());
              const { data } = await apiJson("/api/admin/audit?" + params.toString(), { headers: authHeaders() });
              if (data.success) setEntries((prev) => [...prev, ...data.entries]);
            }}>Load more ↓</Btn>
          )}
        </div>
      </Card>
    </div>
  );
}
