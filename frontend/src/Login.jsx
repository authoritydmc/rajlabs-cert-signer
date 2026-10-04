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

  async function ssoLogin() {
    setError("");
    setBusy(true);
    try {
      // Edge (Traefik ForwardAuth) already validated the Authentik session;
      // backend/app/auth.py maps X-authentik-* headers to an admin session.
      // If the Authentik session expired, the edge answers this XHR with a
      // cross-origin 302 that fetch rejects — reload so the edge can send
      // the browser to Authentik login and back to this page.
      const res = await apiFetch("/api/auth/me");
      const data = await res.json().catch(() => ({}));
      if (res.ok && (data.username || data.email || data.success)) {
        onDone();
      } else if (res.status === 401) {
        setError("SSO session is not an admin — use admin password login below.");
      } else {
        window.location.reload();
      }
    } catch (err) {
      window.location.reload();
    }
    setBusy(false);
  }

  return (
    <div className="fixed inset-0 z-[1000] flex items-center justify-center bg-black/85 p-4 backdrop-blur">
      <form onSubmit={submit} className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-6 sm:p-8">
        <h2 className="text-2xl font-extrabold text-cyan-400">Enterprise PKI Signer</h2>
        <p className="text-sm text-slate-400 mb-5">Sign in with your RajLabs SSO account. Password login is deprecated and admin-only.</p>
        {error && <div className="mb-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div>}
        {baseNotice && <div className="mb-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">{baseNotice}</div>}
        <Btn color="cyan" type="button" onClick={ssoLogin} disabled={busy} className="w-full py-2.5">
          {busy ? "Checking SSO…" : "Continue with SSO (Authentik)"}
        </Btn>
        <details className="mt-4 rounded-lg border border-slate-800">
          <summary className="cursor-pointer px-3 py-2 text-xs text-slate-400">Admin password login (deprecated)</summary>
          <div className="px-3 pb-3">
          <Field label="Admin username">
            <input value={user} onChange={(e) => setUser(e.target.value)} className={inp} autoComplete="username" />
          </Field>
          <Field label="Admin password">
            <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} className={inp}
              placeholder="Get password from your hosting dashboard" autoComplete="current-password" />
          </Field>
          <Btn color="slate" type="submit" disabled={busy} className="mt-4 w-full py-2.5">
            {busy ? "Signing in…" : "Sign in with password (admin only)"}
          </Btn>
          </div>
        </details>
        <p className="mt-3 text-center text-[11px] text-slate-500">
          Trouble signing in? Contact your administrator.
        </p>
      </form>
    </div>
  );
}
