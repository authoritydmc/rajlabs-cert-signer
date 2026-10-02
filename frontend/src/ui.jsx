import { createContext, useCallback, useContext, useState } from "react";

const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastHost({ children }) {
  const [items, setItems] = useState([]);
  const push = useCallback((msg, isErr = false) => {
    const id = Math.random().toString(36).slice(2);
    setItems((xs) => [...xs, { id, msg, isErr }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 6000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="fixed top-4 right-4 z-[2000] flex flex-col gap-2 max-w-md">
        {items.map((t) => (
          <div
            key={t.id}
            className={`rounded-xl border px-4 py-3 shadow-2xl text-sm ${
              t.isErr
                ? "border-red-500/40 bg-red-950 text-red-200"
                : "border-emerald-500/40 bg-emerald-950 text-emerald-100"
            }`}
          >
            {t.msg}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const Card = ({ children, className = "" }) => (
  <div className={`rounded-xl border border-slate-800 bg-slate-900/90 p-4 sm:p-5 shadow-lg shadow-black/20 ${className}`}>{children}</div>
);

export const Btn = ({ children, onClick, color = "cyan", className = "", type = "button", disabled }) => {
  const colors = {
    cyan: "bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400 active:bg-cyan-600 shadow-md shadow-cyan-500/20",
    outline: "border border-slate-600 text-slate-200 hover:bg-slate-800 hover:border-slate-500",
    danger: "bg-red-600 text-white hover:bg-red-500 active:bg-red-700 shadow-md shadow-red-600/20",
    ghost: "border border-slate-700 text-slate-300 hover:border-cyan-500 hover:text-cyan-300",
    emerald: "bg-emerald-500 text-slate-950 font-bold hover:bg-emerald-400 active:bg-emerald-600 shadow-md shadow-emerald-500/20",
  };
  return (
    <button type={type} disabled={disabled} onClick={onClick}
      className={`rounded-lg px-3 sm:px-4 py-2 text-sm font-semibold transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed ${colors[color] || colors.cyan} ${className}`}>
      {children}
    </button>
  );
};

export const Field = ({ label, children, hint }) => (
  <label className="block text-xs font-semibold text-slate-300">
    <div className="flex items-center justify-between mb-1">
      <span>{label}</span>
      {hint && <span className="text-[10px] text-slate-500 font-normal">{hint}</span>}
    </div>
    {children}
  </label>
);

export const inp =
  "w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors";

export function Modal({ title, onClose, children, wide }) {
  return (
    <div className="fixed inset-0 z-[1500] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200"
      onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`w-full ${wide ? "max-w-3xl" : "max-w-xl"} max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700/80 bg-slate-900 p-5 sm:p-6 shadow-2xl shadow-cyan-950/20`}>
        <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
          <h3 className="font-bold text-lg text-cyan-300">{title}</h3>
          <button onClick={onClose} className="rounded-lg border border-slate-700 px-2.5 py-1 text-xs text-slate-400 hover:text-white hover:bg-slate-800 transition">
            Close ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Empty({ children }) {
  return <div className="p-6 text-center text-sm text-slate-500 border border-dashed border-slate-800 rounded-xl">{children}</div>;
}

export function formatDaysHuman(days) {
  if (days === "" || days === null || days === undefined) {
    return { human: "No duration specified", date: null, isEmpty: true };
  }
  const d = parseInt(days, 10);
  if (isNaN(d) || d < 0) {
    return { human: "Invalid duration", date: null, isError: true };
  }
  if (d === 0) {
    return { human: "0 days (Expires immediately)", date: new Date().toLocaleDateString(), isError: true };
  }

  const now = new Date();
  const exp = new Date(now.getTime() + d * 86400000);
  const dateStr = exp.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

  let human = "";
  if (d === 1) human = "1 day";
  else if (d < 7) human = `${d} days`;
  else if (d === 7) human = "1 week (7 days)";
  else if (d === 14) human = "2 weeks (14 days)";
  else if (d === 30) human = "1 month (30 days)";
  else if (d === 60) human = "2 months (60 days)";
  else if (d === 90) human = "3 months (90 days) · ACME default";
  else if (d === 180) human = "6 months (180 days)";
  else if (d === 365) human = "1 year (365 days)";
  else if (d === 730) human = "2 years (730 days)";
  else if (d === 825) human = "≈ 2.25 years (825 days · Max leaf)";
  else if (d === 1095) human = "3 years (1,095 days)";
  else if (d === 1825) human = "5 years (1,825 days)";
  else if (d === 3650) human = "10 years (3,650 days)";
  else if (d === 5475) human = "15 years (5,475 days)";
  else if (d === 7300) human = "20 years (7,300 days)";
  else if (d >= 365) {
    const years = Math.floor(d / 365);
    const remDays = d % 365;
    const months = Math.round(remDays / 30.42);
    if (months === 0) human = `≈ ${years} year${years > 1 ? "s" : ""} (${d.toLocaleString()} days)`;
    else if (months === 12) human = `≈ ${years + 1} years (${d.toLocaleString()} days)`;
    else human = `≈ ${years} yr${years > 1 ? "s" : ""}, ${months} mo${months > 1 ? "s" : ""} (${d.toLocaleString()} days)`;
  } else if (d >= 30) {
    const months = Math.floor(d / 30.42);
    const remDays = Math.round(d % 30.42);
    if (remDays === 0) human = `≈ ${months} month${months > 1 ? "s" : ""} (${d} days)`;
    else human = `≈ ${months} mo${months > 1 ? "s" : ""}, ${remDays}d (${d} days)`;
  } else {
    human = `${d} days`;
  }

  return { human, date: dateStr };
}

/**
 * Dropdown + manual number input with real-time human readable calculation
 */
export function DaysSelector({
  value,
  onChange,
  presets = [],
  min = 1,
  max,
  allowEmpty = false,
  emptyLabel = "Never (No expiry)",
  placeholder = "e.g. 90",
  className = "",
}) {
  const currentStr = value === null || value === undefined ? "" : String(value);
  const isKnownPreset = presets.some((p) => String(p.value) === currentStr);
  const [mode, setMode] = useState(isKnownPreset ? currentStr : "custom");

  // Sync mode if value changes externally
  const selectedMode = isKnownPreset ? currentStr : "custom";

  function handleSelectChange(e) {
    const val = e.target.value;
    if (val === "custom") {
      setMode("custom");
    } else {
      setMode(val);
      onChange(val);
    }
  }

  const durationInfo = allowEmpty && currentStr === ""
    ? { human: emptyLabel, date: "No expiration", isNever: true }
    : formatDaysHuman(currentStr);

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex gap-2">
        <select
          value={selectedMode}
          onChange={handleSelectChange}
          className={`${inp} shrink-0 ${selectedMode === "custom" ? "w-1/2" : "w-full"} cursor-pointer`}
        >
          {allowEmpty && <option value="">{emptyLabel}</option>}
          {presets.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
          <option value="custom">⚙️ Custom days…</option>
        </select>

        {selectedMode === "custom" && (
          <div className="relative flex-1">
            <input
              type="number"
              min={min}
              max={max}
              value={currentStr}
              onChange={(e) => onChange(e.target.value)}
              placeholder={placeholder}
              className={`${inp} pr-12`}
            />
            <span className="absolute right-3 top-2 text-xs text-slate-500 pointer-events-none">days</span>
          </div>
        )}
      </div>

      {/* Real-time Human Readable Pill */}
      {currentStr !== "" || allowEmpty ? (
        <div
          className={`flex items-center justify-between gap-2 rounded-md px-2.5 py-1 text-[11px] font-medium transition-all ${
            durationInfo.isNever
              ? "bg-slate-800/80 text-cyan-300 border border-slate-700"
              : durationInfo.isError
              ? "bg-red-500/10 text-red-300 border border-red-500/20"
              : "bg-cyan-500/10 text-cyan-200 border border-cyan-500/20"
          }`}
        >
          <span className="flex items-center gap-1.5 truncate">
            <span>⏱️</span>
            <span className="font-semibold">{durationInfo.human}</span>
          </span>
          {durationInfo.date && (
            <span className="shrink-0 text-slate-400 font-normal">
              📅 Exp: <span className="text-slate-200 font-medium">{durationInfo.date}</span>
            </span>
          )}
        </div>
      ) : null}
    </div>
  );
}

export const POPULAR_COUNTRIES = [
  { code: "US", name: "United States (US)" },
  { code: "IN", name: "India (IN)" },
  { code: "GB", name: "United Kingdom (GB)" },
  { code: "DE", name: "Germany (DE)" },
  { code: "CA", name: "Canada (CA)" },
  { code: "AU", name: "Australia (AU)" },
  { code: "FR", name: "France (FR)" },
  { code: "NL", name: "Netherlands (NL)" },
  { code: "SG", name: "Singapore (SG)" },
  { code: "JP", name: "Japan (JP)" },
  { code: "CH", name: "Switzerland (CH)" },
  { code: "SE", name: "Sweden (SE)" },
  { code: "BR", name: "Brazil (BR)" },
  { code: "AE", name: "United Arab Emirates (AE)" },
  { code: "IE", name: "Ireland (IE)" },
  { code: "ES", name: "Spain (ES)" },
  { code: "IT", name: "Italy (IT)" },
  { code: "NZ", name: "New Zealand (NZ)" },
];

export function CountrySelect({ value, onChange, className = "" }) {
  const upper = (value || "").toUpperCase().slice(0, 2);
  const isPopular = POPULAR_COUNTRIES.some((c) => c.code === upper);
  const [isCustom, setIsCustom] = useState(!isPopular && upper !== "");

  function handleDropdownChange(e) {
    const val = e.target.value;
    if (val === "CUSTOM") {
      setIsCustom(true);
    } else {
      setIsCustom(false);
      onChange(val);
    }
  }

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex gap-2">
        <select
          value={isCustom ? "CUSTOM" : upper || "US"}
          onChange={handleDropdownChange}
          className={`${inp} shrink-0 ${isCustom ? "w-2/3" : "w-full"} cursor-pointer`}
        >
          {POPULAR_COUNTRIES.map((c) => (
            <option key={c.code} value={c.code}>
              {c.name}
            </option>
          ))}
          <option value="CUSTOM">🌐 Other / Custom (2-letter code)…</option>
        </select>
        {isCustom && (
          <input
            value={upper}
            onChange={(e) => onChange(e.target.value.toUpperCase().replace(/[^A-Z]/g, "").slice(0, 2))}
            maxLength={2}
            placeholder="XX"
            className={`${inp} uppercase text-center font-bold tracking-wider flex-1`}
          />
        )}
      </div>
    </div>
  );
}
