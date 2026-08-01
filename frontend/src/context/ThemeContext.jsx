import { createContext, useContext, useEffect, useState } from "react";

const ThemeContext = createContext(null);

// The pre-paint script in index.html has already set data-theme on <html>, so
// seed from there to stay in sync and avoid a flicker on first render.
function getInitialTheme() {
  if (typeof document !== "undefined") {
    const attr = document.documentElement.dataset.theme;
    if (attr === "dark" || attr === "light") return attr;
  }
  return "light";
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(getInitialTheme);

  // Reflect the choice onto <html> (drives the CSS variables) and remember it.
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("theme", theme);
    } catch {
      /* storage unavailable (e.g. private mode) — the in-memory theme still works */
    }
  }, [theme]);

  const setTheme = (t) => setThemeState(t === "dark" ? "dark" : "light");
  const toggleTheme = () =>
    setThemeState((t) => (t === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
