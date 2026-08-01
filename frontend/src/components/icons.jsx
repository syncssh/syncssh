// Shared line icons — one drawing per resource, used by both the sidebar nav
// and page empty states so the same concept always gets the same glyph.
export function Icon({ children, className = "w-5 h-5" }) {
  return (
    <svg
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

export function ServersIcon({ className }) {
  return (
    <Icon className={className}>
      <rect x="3" y="4" width="18" height="7" rx="1.5" />
      <rect x="3" y="13" width="18" height="7" rx="1.5" />
      <path strokeLinecap="round" d="M7 7.5h.01M7 16.5h.01" />
    </Icon>
  );
}

export function KeyIcon({ className }) {
  return (
    <Icon className={className}>
      <circle cx="8" cy="15" r="4" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.85 12.15 19 4M18 5l2 2M15 8l2 2" />
    </Icon>
  );
}

export function MailIcon({ className }) {
  return (
    <Icon className={className}>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path strokeLinecap="round" strokeLinejoin="round" d="m3 7 9 6 9-6" />
    </Icon>
  );
}
