import { useEffect, useState } from "react";
import { apiJson, authHeaders } from "../api";
import { Btn, Card, Field, inp, useToast } from "../ui";

export default function Settings() {
  const toast = useToast();
  const [p, setP] = useState({ orgName: "", domainSuffix: "", country: "US", state: "", city: "", defaultDays: 90 });
  const [saved, setSaved] = useState(false);

  async function load() {
    const { data } = await apiJson("/api/admin/profile", { headers: authHeaders() });
    setP({
      orgName: data.orgName || "", domainSuffix: data.domainSuffix || "",
      country: data.country || "US", state: data.state || "", city: data.city || "",
      defaultDays: data.defaultDays || 90,
    });
  }
  useEffect(() => {
    load();
  }, []);

  async function save() {
    const { res } = await apiJson("/api/admin/profile", {
      method: "POST", headers: authHeaders(), body: JSON.stringify(p),
    });
    if (res.ok) {
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } else toast("Failed to save profile defaults.", true);
  }

  const set = (k) => (e) => setP((prev) => ({ ...prev, [k]: e.target.value }));

  return (
    <div>
      <h1 className="text-2xl font-extrabold">Org Profile & Defaults</h1>
      <p className="text-sm text-slate-400 mb-4">Pre-fills issuance forms.</p>
      <Card className="max-w-xl">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Org"><input value={p.orgName} onChange={set("orgName")} className={inp} /></Field>
          <Field label="Domain suffix"><input value={p.domainSuffix} onChange={set("domainSuffix")} className={inp} /></Field>
          <Field label="Country"><input value={p.country} onChange={set("country")} className={inp} /></Field>
          <Field label="State"><input value={p.state} onChange={set("state")} className={inp} /></Field>
          <Field label="City"><input value={p.city} onChange={set("city")} className={inp} /></Field>
          <Field label="Default days"><input value={p.defaultDays} onChange={set("defaultDays")} type="number" className={inp} /></Field>
        </div>
        <div className="mt-4 flex items-center gap-2">
          <Btn color="cyan" onClick={save}>Save Defaults</Btn>
          {saved && <span className="text-sm text-emerald-400">✓ Saved</span>}
        </div>
      </Card>
    </div>
  );
}
