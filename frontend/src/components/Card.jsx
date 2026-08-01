// A panel on the dark base. Borders carry the structure here, not shadows —
// shadows mostly vanish on a near-black background.
export function Card({ children, className = "", ...props }) {
  return (
    <div
      className={`bg-surface border border-line rounded-lg ${className}`}
      {...props}
    >
      {children}
    </div>
  );
}
