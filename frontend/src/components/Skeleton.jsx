// Shimmer placeholders shown while a list or table loads, so the layout
// settles into its final shape instead of popping in after a blank "Loading…".
// Marked aria-hidden — there's nothing here for a screen reader to announce.
export function Skeleton({ className = "" }) {
  return <div className={`animate-pulse rounded bg-line/60 ${className}`} />;
}

// Mimics the stack of list Cards (servers, keys, pubkeys, invites).
export function ListSkeleton({ count = 3 }) {
  return (
    <div className="space-y-3" aria-hidden="true">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="bg-surface border border-line rounded-lg p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 space-y-2.5">
              <Skeleton className="h-4 w-1/3" />
              <Skeleton className="h-3 w-1/2" />
            </div>
            <Skeleton className="h-5 w-16" />
          </div>
          <Skeleton className="h-3 w-2/5 mt-4" />
        </div>
      ))}
    </div>
  );
}

// Mimics a Card-wrapped table (audit log, dashboard members).
export function TableSkeleton({ rows = 6, cols = 5 }) {
  return (
    <div
      className="bg-surface border border-line rounded-lg overflow-hidden"
      aria-hidden="true"
    >
      <div className="border-b border-line px-4 py-3 flex gap-4">
        {Array.from({ length: cols }).map((_, i) => (
          <Skeleton key={i} className="h-3 flex-1" />
        ))}
      </div>
      <div className="divide-y divide-line-soft">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="px-4 py-3 flex gap-4">
            {Array.from({ length: cols }).map((_, c) => (
              <Skeleton key={c} className="h-3 flex-1" />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
