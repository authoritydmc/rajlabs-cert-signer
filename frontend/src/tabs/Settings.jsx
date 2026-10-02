import { useEffect, useState } from "react";
import { apiJson, authHeaders } from "../api";
import { Btn, Card, CountrySelect, DaysSelector, Field, inp, useToast } from "../ui";

const DEFAULT_DAYS_PRESETS = [
  { label: "90 Days · ACME / Let's Encrypt default", value: "90" },
  { label: "30 Days · Short-lived mTLS", value: "30" },
  { label: "180 Days · 6 Months", value: "180" },
  { label: "1 Year · 365 Days", value: "365" },
  { label: "2 Years · 730 Days", value: "730" },
  { label: "825 Days · Max Allowed Leaf Limit", value: "825" },
];

export default function Settings() {
  const toast = useToast();
  const [p, setP] = useState({
    orgName: "",
    domainSuffix: "",
    country: "US",
    state: "",
    city: "",
    defaultDays: 90,
  });
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  async function load() {
    const { data } = await apiJson("/api/admin/profile", { headers: authHeaders() });
    if (data) {
      setP({
        orgName: data.orgName || "",
        domainSuffix: data.domainSuffix || "",
        country: data.country || "US",
        state: data.state || "",
        city: data.city || "",
        defaultDays: data.defaultDays || 90,
      });
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function save() {
    setBusy(true);
    const { res } = await apiJson("/api/admin/profile", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        ...p,
        defaultDays: parseInt(p.defaultDays, 10) || 90,
      }),
    });
    setBusy(false);
    if (res.ok) {
      setSaved(true);
      toast("Organization defaults saved successfully.");
      setTimeout(() => setSaved(false), 3000);
    } else {
      toast("Failed to save profile defaults.", true);
    }
  }

  const set = (k) => (e) => setP((prev) => ({ ...prev, [k]: e.target.value }));
  const setVal = (k, v) => setP((prev) => ({ ...prev, [k]: v }));

  return (
    <div>
      <div className="mb-4">
        <h1 className="text-2xl font-extrabold text-slate-100">Org Profile & System Defaults</h1>
        <p className="text-sm text-slate-400">
          Configure default values for certificate issuance forms and subject information.
        </p>
      </div>

      <Card className="max-w-2xl">
        <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-3">
          Global PKI Identity Defaults
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 mb-4">
          <div>
            <Field label="Organization Name">
              <input
                value={p.orgName}
                onChange={set("orgName")}
                placeholder="Enterprise / Lab Name"
                className={inp}
              />
            </Field>
          </div>

          <div>
            <Field label="Default Domain Suffix">
              <input
                value={p.domainSuffix}
                onChange={set("domainSuffix")}
                placeholder="e.g. corp.internal"
                className={inp}
              />
            </Field>
          </div>

          <div>
            <Field label="Default Country">
              <CountrySelect value={p.country} onChange={(c) => setVal("country", c)} />
            </Field>
          </div>

          <div>
            <Field label="State / Province">
              <input
                value={p.state}
                onChange={set("state")}
                placeholder="e.g. California"
                className={inp}
              />
            </Field>
          </div>

          <div>
            <Field label="City / Locality">
              <input
                value={p.city}
                onChange={set("city")}
                placeholder="e.g. San Francisco"
                className={inp}
              />
            </Field>
          </div>

          <div>
            <Field label="Default Leaf Validity Duration">
              <DaysSelector
                value={p.defaultDays}
                onChange={(d) => setVal("defaultDays", d)}
                presets={DEFAULT_DAYS_PRESETS}
                min={1}
                max={825}
              />
            </Field>
          </div>
        </div>

        <div className="mt-5 pt-3 border-t border-slate-800 flex items-center gap-3">
          <Btn color="cyan" onClick={save} disabled={busy}>
            {busy ? "Saving…" : "Save Defaults"}
          </Btn>
          {saved && (
            <span className="text-sm font-semibold text-emerald-400 flex items-center gap-1">
              <span>✓</span> Saved successfully
            </span>
          )}
        </div>
      </Card>
    </div>
  );
}
