// Mono uppercase chips and the LED status dots that give the dashboard its
// "rack of servers" read. Tones map to the shared accent palette so every
// status across the app speaks the same color language.
const TONES = {
  accent: "bg-accent/12 text-accent",
  warn: "bg-warn/12 text-warn",
  danger: "bg-danger/12 text-danger",
  info: "bg-info/12 text-info",
  violet: "bg-violet/12 text-violet",
  neutral: "bg-line/60 text-muted",
};

export function Badge({ tone = "neutral", className = "", children, ...props }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded
        font-mono text-[0.7rem] uppercase tracking-wide ${TONES[tone] ?? TONES.neutral} ${className}`}
      {...props}
    >
      {children}
    </span>
  );
}

const DOT_TONES = {
  accent: "text-accent",
  warn: "text-warn",
  danger: "text-danger",
  neutral: "text-faint",
};

// A small LED. `glow` adds a soft halo that matches the dot for live states.
// bg-current + currentColor keep the fill and halo locked to one tone.
export function Dot({ tone = "neutral", glow = false, className = "" }) {
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full shrink-0 bg-current ${DOT_TONES[tone] ?? DOT_TONES.neutral} ${className}`}
      style={glow ? { boxShadow: `0 0 6px 0 currentColor` } : undefined}
    />
  );
}
