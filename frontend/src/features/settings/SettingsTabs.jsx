import { NavLink } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

// Route-backed tabs under the Settings header. The Workspace tab is simply
// not rendered for members — they have nothing to do there, and the backend
// re-checks OWNER/ADMIN on every endpoint anyway.
const TABS = [
  { to: "/settings", label: "Account", end: true },
  { to: "/settings/workspace", label: "Workspace", adminOnly: true },
];

export function SettingsTabs() {
  const { role } = useAuth();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const tabs = TABS.filter((t) => !t.adminOnly || isAdmin);
  if (tabs.length < 2) return null;
  return (
    <nav className="flex gap-6 border-b border-line mb-6" aria-label="Settings sections">
      {tabs.map((t) => (
        <NavLink
          key={t.to}
          to={t.to}
          end={t.end}
          className={({ isActive }) =>
            `pb-2 -mb-px font-mono text-xs uppercase tracking-wider border-b-2 transition-colors
            ${isActive ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"}`
          }
        >
          {t.label}
        </NavLink>
      ))}
    </nav>
  );
}
