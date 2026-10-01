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
  <div className={`rounded-xl border border-slate-800 bg-slate-900 p-4 sm:p-5 ${className}`}>{children}</div>
);

export const Btn = ({ children, onClick, color = "cyan", className = "", type = "button", disabled }) => {
  const colors = {
    cyan: "bg-cyan-500 text-black hover:opacity-90",
    outline: "border border-slate-600 hover:bg-slate-800",
    danger: "bg-red-500 text-white hover:opacity-90",
    ghost: "border border-slate-700 text-slate-300 hover:border-cyan-500",
  };
  return (
    <button type={type} disabled={disabled} onClick={onClick}
      className={`rounded-lg px-3 sm:px-4 py-2 text-sm font-semibold disabled:opacity-50 ${colors[color]} ${className}`}>
      {children}
    </button>
  );
};

export const Field = ({ label, children }) => (
  <label className="block text-xs font-semibold text-slate-300">
    <span className="mb-1 block">{label}</span>
    {children}
  </label>
);

export const inp =
  "w-full rounded-lg border border-slate-700 bg-black px-3 py-2 text-sm text-slate-100";

export function Modal({ title, onClose, children, wide }) {
  return (
    <div className="fixed inset-0 z-[1500] flex items-center justify-center bg-black/80 p-4"
      onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`w-full ${wide ? "max-w-3xl" : "max-w-xl"} max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-5 sm:p-6`}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-bold text-cyan-300">{title}</h3>
          <button onClick={onClose} className="rounded border border-slate-600 px-2 py-1 text-xs">Close ✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Empty({ children }) {
  return <div className="p-4 text-center text-sm text-slate-500">{children}</div>;
}
