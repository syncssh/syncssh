import { Link, useSearchParams } from "react-router-dom";
import { AuthLayout } from "../../layouts/AuthLayout";
import { LoginForm } from "./LoginForm";

export function AuthPage() {
  // The backend's password-reset flow lands here with ?reset=done.
  const [searchParams] = useSearchParams();
  const passwordReset = searchParams.get("reset") === "done";

  return (
    <AuthLayout>
      {passwordReset && (
        <div className="bg-accent/10 border border-accent/30 text-accent text-sm p-3 rounded mb-4">
          Password changed. Sign in with your new password.
        </div>
      )}
      <LoginForm />
      <p className="mt-5 text-center text-sm text-muted">
        No account?{" "}
        <Link to="/signup" className="text-accent hover:underline">Sign up</Link>
      </p>
    </AuthLayout>
  );
}