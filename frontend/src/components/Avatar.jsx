// Initial tile — first letter of the user's email (falls back to username).
// Deliberately no Gravatar: fetching avatar hashes from a third party leaks
// email-derived identifiers and the viewer's IP, and breaks air-gapped installs.
export function Avatar({ username, email, className = "w-8 h-8" }) {
  const letter = (email || username || "?").charAt(0).toUpperCase();
  return (
    <span
      // NOTE: don't use `text-base` here — the theme defines a color named
      // `base`, so Tailwind resolves `text-base` as a color (the page
      // background!) instead of a font size. `text-[1.05rem]` is size-only.
      className={`shrink-0 rounded bg-accent/15 text-accent font-mono font-semibold text-[1.05rem]
        flex items-center justify-center ${className}`}
    >
      {letter}
    </span>
  );
}
