import { APP_RELEASE_DATE, APP_VERSION, CHANGELOG_ENTRIES } from "./changelog";
import { Btn, Modal } from "./ui";

export default function ChangelogModal({ onClose }) {
  return (
    <Modal title="📜 Release Notes & Changelog" onClose={onClose} wide>
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xl font-extrabold text-slate-100">Enterprise PKI Signer</span>
            <span className="rounded-full bg-cyan-500/20 border border-cyan-500/40 px-2.5 py-0.5 text-xs font-bold text-cyan-300 mono">
              v{APP_VERSION}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">Latest release · {APP_RELEASE_DATE}</p>
        </div>
      </div>

      <div className="space-y-6">
        {CHANGELOG_ENTRIES.map((entry) => (
          <div
            key={entry.version}
            className={`rounded-xl border p-4 sm:p-5 ${
              entry.current
                ? "border-cyan-500/40 bg-slate-900/90 shadow-lg shadow-cyan-950/20"
                : "border-slate-800 bg-slate-950/60"
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <span className="mono text-base font-bold text-slate-100">v{entry.version}</span>
                {entry.current && (
                  <span className="rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-bold uppercase">
                    Current Version
                  </span>
                )}
              </div>
              <span className="text-xs text-slate-500">{entry.date}</span>
            </div>

            <h4 className="text-sm font-semibold text-cyan-200 mb-3">{entry.title}</h4>

            {entry.sections ? (
              <div className="space-y-3">
                {entry.sections.map((sec) => (
                  <div key={sec.type} className="text-xs">
                    <span
                      className={`inline-block font-bold text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded mb-1.5 ${
                        sec.type === "Added"
                          ? "bg-emerald-500/20 text-emerald-300"
                          : sec.type === "Enhanced"
                          ? "bg-cyan-500/20 text-cyan-300"
                          : sec.type === "Security"
                          ? "bg-purple-500/20 text-purple-300"
                          : "bg-amber-500/20 text-amber-300"
                      }`}
                    >
                      {sec.type}
                    </span>
                    <ul className="list-disc list-inside space-y-1 text-slate-300 pl-1 leading-relaxed">
                      {sec.items.map((item, idx) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            ) : (
              <ul className="list-disc list-inside space-y-1 text-xs text-slate-300 leading-relaxed">
                {entry.highlights.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>

      <div className="mt-5 pt-3 border-t border-slate-800 flex justify-end">
        <Btn color="cyan" onClick={onClose}>
          Close Release Notes
        </Btn>
      </div>
    </Modal>
  );
}
