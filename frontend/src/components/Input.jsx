export function Input({ label, error, className = "", ...props }) {
  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <label className="text-xs font-mono uppercase tracking-wider text-muted">
          {label}
        </label>
      )}
      <input
        className={`px-3 py-2 rounded bg-base border text-sm text-ink placeholder:text-faint
          focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent/50
          ${error ? "border-danger" : "border-line"} ${className}`}
        {...props}
      />
      {error && <span className="text-sm text-danger">{error}</span>}
    </div>
  );
}
