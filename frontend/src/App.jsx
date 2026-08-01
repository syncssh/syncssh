import { useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from "react-router";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { ThemeProvider } from "./context/ThemeContext";
import { bindNavigate } from "./api/navigation";
import { AuthPage } from "./features/auth/AuthPage";
import { SignupPage } from "./features/auth/SignupPage";
import { DashboardPage } from "./features/dashboard/DashboardPage";
import { ServerListPage } from "./features/servers/ServerListPage";
import { KeyListPage } from "./features/keys/KeyListPage";
import { InviteListPage } from "./features/invites/InviteListPage";
import { PubkeyListPage } from "./features/pubkeys/PubkeyListPage";
import { AuditLogPage } from "./features/audit/AuditLogPage";
import { SettingsPage } from "./features/settings/SettingsPage";
import { WorkspaceSettingsPage } from "./features/settings/WorkspaceSettingsPage";
import { ToastContainer } from "./components/Toast";
import { ConfirmProvider } from "./components/ConfirmDialog";

// Hands the router's navigate to the axios layer so a 401 can redirect
// in-app instead of triggering a full-page reload. Must live inside
// <BrowserRouter>. Renders nothing.
function NavigationBinder() {
  const navigate = useNavigate();
  useEffect(() => {
    bindNavigate(navigate);
    return () => bindNavigate(null);
  }, [navigate]);
  return null;
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  return user ? children : <Navigate to="/login" />;
}

function App() {
  return (
    <ThemeProvider>
    <AuthProvider>
      <ConfirmProvider>
      <BrowserRouter>
        <NavigationBinder />
        <Routes>
          <Route path="/login" element={<AuthPage />} />
          <Route path="/signup" element={<SignupPage />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <DashboardPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/servers"
            element={
              <ProtectedRoute>
                <ServerListPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/keys"
            element={
              <ProtectedRoute>
                <KeyListPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/invites"
            element={
              <ProtectedRoute>
                <InviteListPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/pubkeys"
            element={
              <ProtectedRoute>
                <PubkeyListPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/audit"
            element={
              <ProtectedRoute>
                <AuditLogPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <SettingsPage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings/workspace"
            element={
              <ProtectedRoute>
                <WorkspaceSettingsPage />
              </ProtectedRoute>
            }
          />
        </Routes>
      </BrowserRouter>
      <ToastContainer />
      </ConfirmProvider>
    </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
