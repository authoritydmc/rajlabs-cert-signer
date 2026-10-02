import { useCallback, useEffect, useState } from "react";
import { API_BASE, apiJson, setApiBase, token } from "./api";
import ChangelogModal from "./ChangelogModal";
import { APP_VERSION } from "./changelog";
import Login from "./Login";
import Wizard from "./Wizard";
import { ToastHost } from "./ui";
import Overview from "./tabs/Overview";
import Status from "./tabs/Status";
import CAs from "./tabs/CAs";
import Issue from "./tabs/Issue";
import Certs from "./tabs/Certs";
import Viewer from "./tabs/Viewer";
import Tokens from "./tabs/Tokens";
import Audit from "./tabs/Audit";
import Settings from "./tabs/Settings";

const NAV = [
  ["overview", "📊 Overview"],
  ["status", "💓 Connection Status"],
  ["cas", "🏛️ Intermediate CAs"],
  ["issue", "✍️ Issue Certificate"],
  ["certs", "📜 Issued Certificates"],
  ["viewer", "🔍 Cert Viewer"],
  ["tokens", "🔑 API Tokens"],
  ["audit", "🧾 Audit Logs"],
  ["settings", "⚙️ Org Profile"],
];

function Shell() {
  const [authed, setAuthed] = useState(!!token());
  const [tab, setTab] = useState("overview");
  const [status, setStatus] = useState(null);
  const [latency, setLatency] = useState(null);
  const [wizard, setWizard] = useState(false);
  const [showChangelog, setShowChangelog] = useState(false);
  const [initPass, setInitPass] = useState("");
  const [baseNotice, setBaseNotice] = useState("");

  const refreshStatus = useCallback(async () => {
    const t0 = performance.now();
    try {
      const { data } = await apiJson("/api/v1/status");
      setLatency(Math.round(performance.now() - t0));
      if (data && (data.code || data.status)) setStatus(data);
    } catch {}
  }, []);

  const checkSetup = useCallback(async () => {
    try {
      const { data } = await apiJson("/api/auth/setup-status");
      if (data.basePath) {
        setApiBase(data.basePath);
        if (data.basePath) setBaseNotice(`Sub-path mode: API base is ${data.basePath} (auto-detected).`);
      }
      if (data.initialPassword) setInitPass(data.initialPassword);
      if (data.isFirstRun || window.location.pathname.endsWith("/onboarding")) setWizard(true);
    } catch {}
  }, []);

  useEffect(() => {
    checkSetup();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (authed) refreshStatus();
  }, [authed, refreshStatus]);

  function logout() {
    localStorage.removeItem("pki_token");
    location.reload();
  }

  if (!authed) {
    return (
      <>
        <Login
          baseNotice={baseNotice || (API_BASE ? `Sub-path mode: API base is ${API_BASE}.` : "")}
          onDone={() => setAuthed(true)}
        />
        {wizard && <Wizard initialPassword={initPass} onClose={() => setWizard(false)} />}
      </>
    );
  }

  return (
    <div className="min-h-screen lg:flex">
      <aside className="w-full lg:w-64 shrink-0 border-b lg:border-b-0 lg:border-r border-slate-800 bg-slate-950 flex lg:flex-col justify-between">
        <div>
          <div className="hidden lg:flex items-center justify-between border-b border-slate-800 px-5 py-4">
            <span className="font-extrabold text-cyan-400">🔒 Enterprise PKI</span>
            <button
              onClick={() => setShowChangelog(true)}
              className="rounded-full bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 px-2 py-0.5 text-[10px] font-bold text-cyan-300 mono transition"
              title="View Release Notes & Changelog"
            >
              v{APP_VERSION}
            </button>
          </div>

          <nav className="flex lg:flex-col overflow-x-auto lg:overflow-visible py-2 text-sm w-full">
            {NAV.map(([id, label]) => (
              <a
                key={id}
                onClick={() => setTab(id)}
                className={`whitespace-nowrap flex cursor-pointer items-center gap-2 px-5 py-2.5 text-slate-400 hover:text-white transition-colors ${
                  tab === id
                    ? "text-white bg-cyan-500/10 border-l-[3px] border-cyan-500 font-semibold"
                    : "border-l-[3px] border-transparent"
                }`}
              >
                {label}
              </a>
            ))}
            <a
              onClick={() => setWizard(true)}
              className="whitespace-nowrap flex cursor-pointer items-center gap-2 px-5 py-2.5 text-amber-300 hover:text-amber-100 border-l-[3px] border-transparent font-medium"
            >
              🧙 Setup Wizard
            </a>
            <a
              onClick={() => setShowChangelog(true)}
              className="whitespace-nowrap flex cursor-pointer items-center gap-2 px-5 py-2.5 text-slate-400 hover:text-cyan-300 border-l-[3px] border-transparent text-xs"
            >
              📜 Release Notes & Changelog
            </a>
          </nav>
        </div>

        <div className="hidden lg:block border-t border-slate-800 p-4 space-y-2">
          <div className="flex items-center justify-between text-[11px] text-slate-500 px-1">
            <span>Rajlabs CA Signer</span>
            <button
              onClick={() => setShowChangelog(true)}
              className="hover:text-cyan-400 underline decoration-slate-700"
            >
              v{APP_VERSION} Notes
            </button>
          </div>
          <button
            onClick={logout}
            className="w-full rounded-lg border border-slate-700 hover:border-slate-600 px-3 py-2 text-sm text-slate-300 hover:bg-slate-900 transition"
          >
            Sign Out
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto p-4 sm:p-8">
        {tab === "overview" && <Overview status={status} refresh={refreshStatus} openWizard={() => setWizard(true)} />}
        {tab === "status" && <Status status={status} latency={latency} refresh={refreshStatus} />}
        {tab === "cas" && <CAs onChanged={refreshStatus} openWizard={() => setWizard(true)} />}
        {tab === "issue" && <Issue onChanged={refreshStatus} openWizard={() => setWizard(true)} />}
        {tab === "certs" && <Certs onChanged={refreshStatus} />}
        {tab === "viewer" && <Viewer />}
        {tab === "tokens" && <Tokens />}
        {tab === "audit" && <Audit />}
        {tab === "settings" && <Settings />}
        <div className="lg:hidden mt-6 flex gap-2">
          <button
            onClick={() => setShowChangelog(true)}
            className="flex-1 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300"
          >
            v{APP_VERSION} Changelog
          </button>
          <button
            onClick={logout}
            className="flex-1 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300"
          >
            Sign Out
          </button>
        </div>
      </main>

      {wizard && <Wizard initialPassword={initPass} onClose={() => { setWizard(false); refreshStatus(); }} />}
      {showChangelog && <ChangelogModal onClose={() => setShowChangelog(false)} />}
    </div>
  );
}

export default function App() {
  return (
    <ToastHost>
      <Shell />
    </ToastHost>
  );
}
