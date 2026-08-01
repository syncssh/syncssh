import { useEffect, useState } from "react";
import { logout } from "../api/auth";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { useNavigate, Link, useLocation } from "react-router-dom";
import { Brand } from "../components/Brand";
import { Avatar } from "../components/Avatar";
import { Icon, ServersIcon, KeyIcon, MailIcon } from "../components/icons";

export function MainLayout({ children }) {
  const { user, role, logout: doLogout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const [sidebarOpen, setSidebarOpen] = useState(false);
  // Desktop-only: collapse the sidebar to a narrow icon rail, remembered across
  // visits. The mobile drawer is a separate concern handled by `sidebarOpen`.
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("sidebar-collapsed") === "1"
  );

  const toggleCollapsed = () =>
    setCollapsed((v) => {
      const next = !v;
      localStorage.setItem("sidebar-collapsed", next ? "1" : "0");
      return next;
    });

  const navItems = [
    {
      label: "Dashboard",
      to: "/",
      icon: (
        <Icon>
          <rect x="3" y="3" width="7" height="7" rx="1" />
          <rect x="14" y="3" width="7" height="7" rx="1" />
          <rect x="3" y="14" width="7" height="7" rx="1" />
          <rect x="14" y="14" width="7" height="7" rx="1" />
        </Icon>
      ),
    },
    {
      label: "Servers",
      to: "/servers",
      icon: <ServersIcon />,
    },
    {
      label: "Public Keys",
      to: "/pubkeys",
      icon: <KeyIcon />,
    },
    {
      label: "Invites",
      to: "/invites",
      icon: <MailIcon />,
    },
    ...(isAdmin
      ? [
          {
            label: "Audit Log",
            to: "/audit",
            icon: (
              <Icon>
                <path strokeLinecap="round" d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
              </Icon>
            ),
          },
        ]
      : []),
    // API Keys — hidden pending API auth integration
  ];

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  // Close on Escape, and lock body scroll while the drawer is open.
  useEffect(() => {
    if (!sidebarOpen) return;
    const onKey = (e) => e.key === "Escape" && setSidebarOpen(false);
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [sidebarOpen]);

  const handleLogout = async () => {
    try {
      await logout();
    } catch {
      // Clear local auth state even when the server session is already gone.
    }
    doLogout(null);
    navigate("/login");
  };

  return (
    <div className="min-h-screen flex bg-base">
      {/* Backdrop — mobile only, when drawer is open */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar — off-canvas drawer below lg, static column at lg+ */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 bg-base border-r border-line flex flex-col
          transform transition-transform duration-200 ease-in-out
          lg:sticky lg:top-0 lg:h-screen lg:translate-x-0
          ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}
          ${collapsed ? "lg:w-16" : ""}`}
      >
        <div className={`px-5 py-5 border-b border-line ${collapsed ? "lg:px-2 lg:py-4" : ""}`}>
          <div className={`flex items-start justify-between ${collapsed ? "lg:justify-center" : ""}`}>
            {/* Brand collapses away in the desktop rail; the toggle stays. */}
            <Brand className={`text-xl ${collapsed ? "lg:hidden" : ""}`} />
            <div className="flex items-center">
              {/* Desktop collapse/expand toggle — lives in the sidebar itself. */}
              <button
                onClick={toggleCollapsed}
                className={`hidden lg:block text-muted hover:text-ink p-1 ${collapsed ? "" : "-mr-1"}`}
                aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              {/* Close button — mobile only. */}
              <button
                onClick={() => setSidebarOpen(false)}
                className="lg:hidden text-muted hover:text-ink p-1 -mr-1 -mt-0.5"
                aria-label="Close menu"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
          {/* Who you're signed in as — kept distinct from the brand above.
              Doubles as the entry point to account settings. */}
          {user?.username && (
            <Link
              to="/settings"
              aria-label="Account settings"
              title={collapsed ? `${user.username} — account settings` : "Account settings"}
              className={`flex items-center gap-2.5 mt-4 min-w-0 rounded -mx-1 px-1 py-1 -my-1
                hover:bg-raised/60 transition-colors group
                ${collapsed ? "lg:mt-0 lg:mx-0 lg:px-0 lg:justify-center" : ""}`}
            >
              <Avatar username={user.username} email={user.email} className="w-8 h-8" />
              <div className={`min-w-0 leading-tight ${collapsed ? "lg:hidden" : ""}`}>
                <p className="font-mono text-sm text-ink truncate group-hover:text-accent transition-colors">
                  {user.username}
                </p>
                {role && (
                  <p className="font-mono text-[0.7rem] uppercase tracking-wide text-faint">
                    {role}
                  </p>
                )}
              </div>
            </Link>
          )}
        </div>
        <nav className="flex-1 overflow-y-auto py-3">
          {navItems.map((item) => {
            const active = location.pathname === item.to;
            return (
              <Link
                key={item.to}
                to={item.to}
                aria-current={active ? "page" : undefined}
                aria-label={item.label}
                title={collapsed ? item.label : undefined}
                className={`flex items-center gap-2.5 mx-2 px-3 py-2 rounded font-mono text-sm transition-colors
                  ${collapsed ? "lg:justify-center lg:px-0" : ""}
                  ${
                    active
                      ? "bg-raised text-accent"
                      : "text-muted hover:text-ink hover:bg-raised/60"
                  }`}
              >
                <span className={`shrink-0 ${active ? "text-accent" : "text-faint"}`}>
                  {item.icon}
                </span>
                <span className={collapsed ? "lg:hidden" : ""}>{item.label}</span>
              </Link>
            );
          })}
        </nav>
        <button
          onClick={toggleTheme}
          title={collapsed ? (theme === "dark" ? "Light mode" : "Dark mode") : undefined}
          className={`mx-2 px-3 py-2 rounded font-mono text-sm text-muted hover:text-ink text-left hover:bg-raised/60 transition-colors flex items-center gap-2 ${collapsed ? "lg:justify-center lg:px-0" : ""}`}
          aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        >
          {theme === "dark" ? (
            // Sun — clicking switches to light
            <svg className="w-4 h-4 text-faint" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="4" />
              <path strokeLinecap="round" d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
            </svg>
          ) : (
            // Moon — clicking switches to dark
            <svg className="w-4 h-4 text-faint" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
          )}
          <span className={collapsed ? "lg:hidden" : ""}>
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </span>
        </button>
        <button
          onClick={handleLogout}
          title={collapsed ? "Sign out" : undefined}
          className={`mx-2 mb-3 px-3 py-2 rounded font-mono text-sm text-muted hover:text-ink text-left hover:bg-raised/60 transition-colors flex items-center gap-2 ${collapsed ? "lg:justify-center lg:px-0" : ""}`}
        >
          <span className="text-faint">⏻</span>
          <span className={collapsed ? "lg:hidden" : ""}>Sign out</span>
        </button>
      </aside>

      {/* Right column: mobile top bar + main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar — mobile only, hosts the hamburger */}
        <header className="lg:hidden sticky top-0 z-20 flex items-center gap-3 bg-surface border-b border-line px-4 h-14">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-1 -ml-1 text-muted hover:text-ink"
            aria-label="Open menu"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <Brand className="text-lg" />
        </header>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
