import { useState } from "react";
import { apiJson, authHeaders, errText } from "../api";
import { Btn, Card, Field, inp, useToast } from "../ui";

export default function Viewer() {
  const toast = useToast();
  const [text, setText] = useState("");
  const [parsed, setParsed] = useState(null);

  async function inspect(content) {
    const { data } = await apiJson("/api/admin/parse-cert", {
      method: "POST", headers: authHeaders(), body: JSON.stringify({ content }),
    });
    if (data.success) setParsed(data);
    else toast(errText(data, "Parse failed"), true);
  }

  function onFile(e) {
    const f = e.target.files[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => inspect(r.result);
    if (/\.(der|cer)$/i.test(f.name)) r.readAsDataURL(f);
    else r.readAsText(f);
  }

  return (
    <div>
      <h1 className="text-2xl font-extrabold">Certificate & CSR Inspector</h1>
      <p className="text-sm text-slate-400 mb-4">Paste PEM or drop a file.</p>
      <Card className="mb-4">
        <Field label="Certificate / CSR (PEM)">
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={4}
            placeholder="-----BEGIN CERTIFICATE-----…" className={`${inp} mono text-xs`} />
        </Field>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Btn color="cyan" onClick={() => (text.trim() ? inspect(text.trim()) : toast("Paste a certificate first"))}>Inspect</Btn>
          <input type="file" onChange={onFile} className="text-xs text-slate-400" />
        </div>
      </Card>
      {parsed && (
        <Card className="border-cyan-500/40">
          <h3 className="font-bold text-cyan-300">{parsed.kind || "Certificate"}</h3>
          <div className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
            <div><span className="text-slate-400 text-xs">Subject:</span><div className="mono text-xs break-all">{parsed.subject || "-"}</div></div>
            <div><span className="text-slate-400 text-xs">Issuer:</span><div className="mono text-xs break-all">{parsed.issuer || "-"}</div></div>
            <div><span className="text-slate-400 text-xs">Serial:</span><div className="mono text-xs">{parsed.serial || "-"}</div></div>
            <div><span className="text-slate-400 text-xs">Validity:</span><div className="text-xs">{parsed.validFrom || "-"} → {parsed.validTo || "-"}</div></div>
          </div>
          <div className="mt-2 text-xs"><span className="text-slate-400">SANs:</span> <span className="mono text-cyan-300">{parsed.sans || "None"}</span></div>
          <pre className="mt-3 max-h-96 overflow-auto rounded-lg bg-black p-3 text-[11px] text-sky-300 mono">{parsed.fullText || ""}</pre>
        </Card>
      )}
    </div>
  );
}
