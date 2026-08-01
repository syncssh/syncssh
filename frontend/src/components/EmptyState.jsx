import { Card } from "./Card";

// A friendlier empty state than a bare sentence: a muted glyph, the message,
// an optional hint line, and an optional primary call-to-action so the next
// step is one click away instead of a hunt for the header button.
export function EmptyState({ icon = "∅", title, hint, action, className = "" }) {
  return (
    <Card className={`p-12 flex flex-col items-center text-center ${className}`}>
      <div className="text-3xl text-faint mb-3 font-mono leading-none" aria-hidden="true">
        {icon}
      </div>
      <p className="text-muted">{title}</p>
      {hint && <p className="text-sm text-faint mt-1 max-w-sm">{hint}</p>}
      {action && <div className="mt-5">{action}</div>}
    </Card>
  );
}
