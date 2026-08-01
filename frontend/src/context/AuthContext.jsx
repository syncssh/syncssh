import { createContext, useContext, useState, useEffect, useRef } from "react";
import { getMe, getCsrf, updateMe } from "../api/auth";
import { getOrg } from "../api/org";
import { useTheme } from "./ThemeContext";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [role, setRole] = useState(null);
  const [organization, setOrganization] = useState(null);
  const [emailDeliveryConfigured, setEmailDeliveryConfigured] = useState(true);
  // Edition feature flags from /me. Empty until it resolves; treat a missing
  // flag as disabled so gated UI stays hidden rather than flashing in.
  const [features, setFeatures] = useState({});
  const [loading, setLoading] = useState(true);
  const { theme, setTheme } = useTheme();
  // Last theme the server knows about; null until /me resolves so we never
  // push before knowing whether a server-side preference exists.
  const serverTheme = useRef(null);

  // A saved server preference wins over localStorage; an unset one ("") keeps
  // the local choice, which the sync effect below then adopts server-side.
  const applyServerTheme = (userData) => {
    const t = userData?.prefs?.theme ?? "";
    serverTheme.current = t;
    if (t) setTheme(t);
  };

  const applyOrganization = (data) => {
    setRole(data.your_role);
    setOrganization(data.org);
  };

  useEffect(() => {
    getCsrf().then(() => getMe()).then((res) => {
        setUser(res.data.user);
        applyServerTheme(res.data.user);
        setEmailDeliveryConfigured(res.data.email_delivery_configured !== false);
        setFeatures(res.data.features || {});
        // Fetch org to get role
        return getOrg();
      })
      .then((res) => applyOrganization(res.data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Persist theme changes (from the sidebar toggle or the Appearance card)
  // once signed in, so the choice follows the user across devices.
  useEffect(() => {
    if (!user || serverTheme.current === null || theme === serverTheme.current) return;
    serverTheme.current = theme; // optimistic — a lost write just means no sync
    updateMe({ theme }).catch(() => {});
  }, [theme, user]);

  // A 401 from any request (session expired/revoked) clears auth here so the
  // UI can't keep showing a signed-in shell. The client also redirects to
  // /login; this just makes the state honest.
  useEffect(() => {
    const onUnauthorized = () => {
      setUser(null);
      setRole(null);
      setOrganization(null);
    };
    window.addEventListener("auth:unauthorized", onUnauthorized);
    return () => window.removeEventListener("auth:unauthorized", onUnauthorized);
  }, []);

  const login = async (userData) => {
    setUser(userData);
    applyServerTheme(userData);
    // Refresh edition flags: post-login navigation is client-side, so the
    // initial /me effect won't re-run to populate them.
    getMe().then((res) => setFeatures(res.data.features || {})).catch(() => {});
    try {
      const res = await getOrg();
      applyOrganization(res.data);
    } catch {
      setRole(null);
    }
  };
  const logout = () => {
    setUser(null);
    setRole(null);
    setOrganization(null);
  };

  return (
    <AuthContext.Provider value={{ user, role, organization, emailDeliveryConfigured, features, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
