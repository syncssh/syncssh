import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { Button } from "./Button";

const ConfirmContext = createContext(null);

// Promise-based replacement for window.confirm(). Usage:
//   const confirm = useConfirm();
//   if (!(await confirm({ title, message, confirmLabel, danger: true }))) return;
// A bare string is treated as the message.
export function ConfirmProvider({ children }) {
  const [state, setState] = useState(null);

  const confirm = useCallback((opts) => {
    const cfg = typeof opts === "string" ? { message: opts } : opts || {};
    return new Promise((resolve) => {
      setState({
        title: "Are you sure?",
        confirmLabel: "Confirm",
        cancelLabel: "Cancel",
        danger: false,
        ...cfg,
        resolve,
      });
    });
  }, []);

  const close = (result) => {
    setState((s) => {
      s?.resolve(result);
      return null;
    });
  };

  // Esc cancels, Enter confirms — only while a dialog is open.
  useEffect(() => {
    if (!state) return;
    const onKey = (e) => {
      if (e.key === "Escape") close(false);
      if (e.key === "Enter") close(true);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [state]);

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {state && (
        <div
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
          onClick={() => close(false)}
        >
          <div
            className="bg-raised border border-line rounded-lg shadow-xl max-w-md w-full p-6"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
          >
            <h2 className="text-lg font-bold text-ink mb-2">{state.title}</h2>
            {state.message && (
              <p className="text-sm text-muted whitespace-pre-line">{state.message}</p>
            )}
            <div className="flex justify-end gap-3 mt-5">
              <Button variant="secondary" onClick={() => close(false)}>
                {state.cancelLabel}
              </Button>
              <Button
                variant={state.danger ? "danger" : "primary"}
                onClick={() => close(true)}
              >
                {state.confirmLabel}
              </Button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}

export const useConfirm = () => useContext(ConfirmContext);
