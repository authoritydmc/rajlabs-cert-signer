import { useState } from "react";
import { apiJson, authHeaders, errText } from "../api";
import { Btn, Card, Field, inp, useToast } from "../ui";

export default function Issue({ onChanged, openWizard }) {
  const toast = useToast();
  const [cn, setCn] = useState("");
  const [sans, setSans] = useState("");
  const [days, setDays] = useState("90");
  const [ca, setCa] = useState("");
  const [purpose, setPurpose] = useState("");
  const [result, setResult] = useState(null);

  async function submit() {
    const { res, data } = await apiJson("/api/admin/generate-cert", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        commonName: cn, sans, days,
        ca: ca || undefined, purpose: purpose || undefined,
      }),
    });
    if (data.success) {
      setResult(data);
      toast(`Issued serial ${data.serial}${data.caSelection ? " via " + data.caSelection : ""}`);
      onChanged();
    } else {
      if (data.code === "CA_NOT_AVAILABLE") {
        toast(
          <span>{errText(data, "Issuance failed")} <button className="underline" onClick={openWizard}>Open Setup Wizard</button></span>,
          true
        );
      } else toast(errText(data, "Issuance failed"), true);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-extrabold">Issue Leaf Certificate</h1>
      <p className="text-sm text-slate-400 mb-4">Key + CSR + sign in one step.</p>
      <Card className="max-w-xl">
        <div className="mb-3"><Field label="Common Name"><input value={cn} onChange={(e) => setCn(e.target.value)} placeholder="api.example.com" className={inp} /></Field></div>
        <div className="mb-3"><Field label="SANs (comma-separated)"><input value={sans} onChange={(e) => setSans(e.target.value)} className={inp} /></Field></div>
        <div className="mb-3"><Field label="Days"><input value={days} onChange={(e) => setDays(e.target.value)} type="number" className={inp} /></Field></div>
        <div className="grid grid-cols-2 gap-3 mb-3">
          <Field label="Signing CA (optional)">
            <select value={ca} onChange={(e) => setCa(e.target.value)} className={inp}>
              <option value="">Auto (by purpose → active)</option>
              <option>int-server</option><option>int-wifi</option><option>int-iot</option>
            </select>
          </Field>
          <Field label="Purpose (routes CA)">
            <select value={purpose} onChange={(e) => setPurpose(e.target.value)} className={inp}>
              <option value="">Auto</option>
              <option value="server">server / web / TLS</option>
              <option value="wifi">wifi / RADIUS / 802.1X</option>
              <option value="iot">iot / device / MQTT</option>
              <option value="acme">acme</option>
            </select>
          </Field>
        </div>
        <Btn color="cyan" onClick={submit}>Generate & Sign</Btn>
        <p className="mt-2 text-[11px] text-slate-500">
          Routing: explicit CA → purpose map (wifi→int-wifi, iot→int-iot, server→int-server) → active → int-server → first.
        </p>
      </Card>

      {result && (
        <Card className="mt-4 max-w-xl border-emerald-500/40">
          <h3 className="font-bold text-emerald-400 mb-2">✅ Issued (serial {result.serial})</h3>
          <Field label="Private key — save now, shown once"><textarea value={result.privateKey} rows={3} readOnly className={`${inp} mono text-xs`} /></Field>
          <div className="mt-2"><Field label="Full chain"><textarea value={result.fullChain} rows={5} readOnly className={`${inp} mono text-xs`} /></Field></div>
        </Card>
      )}
    </div>
  );
}
