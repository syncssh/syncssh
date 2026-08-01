// The signature: SyncSSH as a shell prompt — the wordmark followed by a
// blinking block caret. The caret respects prefers-reduced-motion (index.css).
export function Brand({ className = "" }) {
  return (
    <span className={`font-mono select-none ${className}`}>
      <span className="font-semibold text-ink">
        sync<span className="text-accent">ssh</span>
      </span>
      <span className="caret" aria-hidden="true" />
    </span>
  );
}
