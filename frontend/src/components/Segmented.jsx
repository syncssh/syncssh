// A small exclusive-choice control for two or three options (e.g. light/dark),
// where a dropdown would hide the alternatives and a toggle has no labels.
export function Segmented({ value, onChange, options, disabled = false, className = "" }) {
  return (
    <div
      role="radiogroup"
      className={`inline-flex rounded border border-line overflow-hidden ${className}`}
    >
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={disabled}
            onClick={() => !active && onChange(opt.value)}
            className={`px-3 py-1.5 font-mono text-xs uppercase tracking-wider transition-colors
              disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer
              ${active ? "bg-accent/15 text-accent" : "bg-transparent text-muted hover:text-ink"}`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
