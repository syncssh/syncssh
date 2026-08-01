import { useEffect, useState } from "react";

let _nextId = 0;

const ICONS = { success: "✓", error: "✕", info: "i" };
const ICON_COLORS = {
  success: "text-accent",
  error: "text-danger",
  info: "text-info",
};

// toast("done")                       → success
// toast("nope", { type: "error" })    → error
// toast("msg", 5000)                  → success, custom duration (back-compat)
export function toast(message, opts = {}) {
  const { type = "success", duration = 3000 } =
    typeof opts === "number" ? { duration: opts } : opts;
  window.dispatchEvent(
    new CustomEvent("toast", { detail: { message, type, duration } }),
  );
}

export function ToastContainer() {
  const [toasts, setToasts] = useState([]);

  useEffect(() => {
    const handler = (e) => {
      // Each toast gets its own id + timers. A single shared timeout (the old
      // approach) let a second toast cancel the first one's removal.
      const id = _nextId++;
      const { message, type, duration } = e.detail;
      setToasts((t) => [...t, { id, message, type, leaving: false }]);
      // Fade out first, then drop it from the list once the transition ends.
      setTimeout(() => {
        setToasts((t) =>
          t.map((x) => (x.id === id ? { ...x, leaving: true } : x)),
        );
        setTimeout(() => {
          setToasts((t) => t.filter((x) => x.id !== id));
        }, 200);
      }, duration);
    };
    window.addEventListener("toast", handler);
    return () => window.removeEventListener("toast", handler);
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 left-4 sm:left-auto z-50 flex flex-col gap-2 items-end">
      {toasts.map((t) => (
        <ToastItem key={t.id} {...t} />
      ))}
    </div>
  );
}

function ToastItem({ message, type, leaving }) {
  // Start hidden, then flip to shown on the next frame so the enter transition
  // actually animates (a freshly-mounted element can't transition from itself).
  const [shown, setShown] = useState(false);
  useEffect(() => {
    const r = requestAnimationFrame(() => setShown(true));
    return () => cancelAnimationFrame(r);
  }, []);

  const visible = shown && !leaving;
  return (
    <div
      className={
        "bg-raised border border-line text-ink text-sm font-mono px-4 py-3 " +
        "rounded-lg shadow-xl flex items-center gap-2.5 max-w-sm " +
        "transition-all duration-200 ease-out " +
        (visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2")
      }
    >
      <span className={ICON_COLORS[type] || "text-accent"}>
        {ICONS[type] || "✓"}
      </span>
      {message}
    </div>
  );
}
