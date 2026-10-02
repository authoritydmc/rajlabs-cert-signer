import { useState } from "react";
import { API_BASE, apiFetch, errText, setApiBase } from "./api";
import { Btn, Field, inp } from "./ui";

export default function Login({ onDone, baseNotice }) {
  const [user, setUser] = useState("admin");
  const [pass, setPass] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const res = await apiFetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });
      const data = await res.json().catch(() => ({}));
      if (data.success) {
        localStorage.setItem("pki_token", data.token);
        onDone();
      } else {
        // If the server tells us its base path, adopt it and retry once
        // (fixes wrong-path logins behind path-based proxies).
        if (data.basePath !== undefined && data.basePath !== API_BASE) {
          setApiBase(data.basePath);
        }
        setError(errText(data, "Login failed"));
      }
    } catch (err) {
      setError(`Cannot reach the signing service — check your network connection or contact your administrator.`);
    }
    setBusy(false);
  }

  return (
    <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/85 p-4 backdrop-blur">
      <form onSubmit={submit} className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-6 sm:p-8">
        <h2 className="text-2xl font-extrabold text-cyan-400">Enterprise PKI Signer</h2>
        <p className="text-sm text-slate-400 mb-5">Sign in to manage CAs, tokens and certificates.</p>
        {error && <div className="mb-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div>}
        {baseNotice && <div className="mb-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">{baseNotice}</div>}
        <div className="mb-3">
          <Field label="Admin username">
            <input value={user} onChange={(e) => setUser(e.target.value)} className={inp} autoComplete="username" />
          </Field>
        </div>
        <Field label="Admin password">
          <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} className={inp}
            placeholder="Get password from your hosting dashboard" autoComplete="current-password" />
        </Field>
        <Btn color="cyan" type="submit" disabled={busy} className="mt-4 w-full py-2.5">
          {busy ? "Signing in…" : "Sign In to Dashboard"}
        </Btn>
        <p className="mt-3 text-center text-[11px] text-slate-500">
          Trouble signing in? Contact your administrator.
        </p>
      </form>
    </div>
  );
}
