import { useState } from "react";
import { useNavigate, Link } from "react-router";
import { signup } from "../../api/auth";
import { useAuth } from "../../context/AuthContext";
import { Button } from "../../components/Button";
import { Input } from "../../components/Input";
import { AuthLayout } from "../../layouts/AuthLayout";

export function SignupPage() {
  const navigate = useNavigate();
  const { login: doLogin } = useAuth();
  const [form, setForm] = useState({
    username: "",
    email: "",
    password1: "",
    password2: "",
    account_type: "solo",
  });
  const [error, setError] = useState("");
  const [pendingEmail, setPendingEmail] = useState(null);

  const handleChange = (e) =>
    setForm((f) => ({ ...f, [e.target.name]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const res = await signup(form);
      if (res.data.verification_required) {
        setPendingEmail(res.data.email);
        return;
      }
      doLogin(res.data.user);
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.error || "Signup failed");
    }
  };

  if (pendingEmail) {
    return (
      <AuthLayout caption="One more step to activate your account">
        <div className="text-center">
          <h1 className="text-xl font-semibold mb-2 text-ink">Check your inbox</h1>
          <p className="text-sm text-muted mb-4">
            We've sent a confirmation link to{" "}
            <span className="font-mono text-accent break-all">{pendingEmail}</span>. Click it to
            activate your account and sign in.
          </p>
          <p className="text-xs text-faint mb-6">
            Didn't receive it? Check spam, or wait a minute and try again.
          </p>
          <Link to="/login" className="text-accent hover:underline text-sm font-mono">
            ← Back to sign in
          </Link>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout caption="Create your account — your own workspace for servers and keys">
      <div>
        {error && (
          <div className="bg-danger/10 border border-danger/30 text-danger text-sm p-3 rounded mb-4">{error}</div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-mono uppercase tracking-wider text-muted block mb-2">Signing up as</label>
            <div className="grid grid-cols-2 gap-2">
              {["solo", "team"].map((type) => (
                <label
                  key={type}
                  className={`flex items-center gap-2 cursor-pointer rounded border px-3 py-2 text-sm transition-colors ${
                    form.account_type === type
                      ? "border-accent/50 bg-accent/10 text-ink"
                      : "border-line text-muted hover:border-faint"
                  }`}
                >
                  <input
                    type="radio"
                    name="account_type"
                    value={type}
                    checked={form.account_type === type}
                    onChange={handleChange}
                  />
                  <span>{type === "solo" ? "Solo developer" : "Team"}</span>
                </label>
              ))}
            </div>
          </div>

          <Input
            label="Username"
            name="username"
            value={form.username}
            onChange={handleChange}
            required
          />
          <Input
            label="Email"
            name="email"
            type="email"
            value={form.email}
            onChange={handleChange}
            required
          />
          <Input
            label="Password"
            name="password1"
            type="password"
            value={form.password1}
            onChange={handleChange}
            required
          />
          <Input
            label="Confirm Password"
            name="password2"
            type="password"
            value={form.password2}
            onChange={handleChange}
            required
          />

          <Button type="submit" className="w-full">Create Account</Button>
        </form>

        <p className="text-sm text-muted mt-5 text-center">
          Already have an account?{" "}
          <Link to="/login" className="text-accent hover:underline">Sign in</Link>
        </p>
      </div>
    </AuthLayout>
  );
}
