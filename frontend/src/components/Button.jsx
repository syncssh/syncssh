function Spinner() {
  return (
    <svg className="w-4 h-4 animate-spin shrink-0" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path className="opacity-90" fill="currentColor" d="M12 2a10 10 0 0 1 10 10h-3a7 7 0 0 0-7-7V2z" />
    </svg>
  );
}

export function Button({ children, variant = "primary", className = "", loading = false, disabled, ...props }) {
  const base =
    "inline-flex items-center justify-center gap-2 px-3.5 py-2 rounded font-mono text-sm font-medium " +
    "transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 " +
    "focus-visible:ring-offset-base disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer";
  const variants = {
    // Emerald prompt action — the one bright thing on the surface. Text uses
    // the dedicated on-accent token so it stays readable in both themes (a
    // bare `text-base` would also collide with Tailwind's font-size utility).
    primary:
      "bg-accent text-[color:var(--color-on-accent)] hover:bg-accent/90 focus-visible:ring-accent",
    secondary:
      "bg-raised text-ink border border-line hover:border-faint hover:bg-line/40 focus-visible:ring-faint",
    danger:
      "bg-danger/15 text-danger border border-danger/30 hover:bg-danger/25 focus-visible:ring-danger",
    ghost:
      "bg-transparent text-muted hover:text-ink hover:bg-raised focus-visible:ring-faint",
  };
  return (
    <button
      className={`${base} ${variants[variant]} ${className}`}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...props}
    >
      {loading && <Spinner />}
      {children}
    </button>
  );
}
