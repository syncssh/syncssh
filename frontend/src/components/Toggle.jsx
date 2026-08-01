// A checkbox styled as a switch. Used where a setting takes effect on flip
// (no separate save), so the on/off state must read at a glance.
export function Toggle({ checked, onChange, label, disabled = false, className = "" }) {
  return (
    <label
      className={`inline-flex items-center gap-2.5 select-none
        ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"} ${className}`}
    >
      <span
        className={`relative inline-block w-9 h-5 rounded-full transition-colors shrink-0
          ${checked ? "bg-accent" : "bg-line"}`}
      >
        <input
          type="checkbox"
          className="peer sr-only"
          checked={checked}
          onChange={onChange}
          disabled={disabled}
        />
        <span
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-surface transition-transform
            peer-focus-visible:ring-2 peer-focus-visible:ring-accent/50
            ${checked ? "translate-x-4" : ""}`}
        />
      </span>
      {label && <span className="text-sm text-muted">{label}</span>}
    </label>
  );
}
