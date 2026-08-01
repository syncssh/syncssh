import { useState } from "react";
import { useNavigate } from "react-router";
import { login as apiLogin } from "../../api/auth";
import { useAuth } from "../../context/AuthContext";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";

export function LoginForm() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const res = await apiLogin(form.username, form.password);
      if (res.data.ok) {
        login(res.data.user);
        navigate("/");
      }
    } catch (err) {
      setError(err.response?.data?.error || "Login failed");
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input
        label="Username"
        type="text"
        value={form.username}
        onChange={(e) => setForm({ ...form, username: e.target.value })}
        required
      />
      <Input
        label="Password"
        type="password"
        value={form.password}
        onChange={(e) => setForm({ ...form, password: e.target.value })}
        required
      />
      {error && <p className="text-sm text-danger">{error}</p>}
      <Button type="submit" className="mt-1">Sign In</Button>
      {/* Plain <a>, not a router Link: the reset flow is served by the backend
          (allauth) until roadmap #6/#8 move it into React. */}
      <a
        href="/accounts/password/reset/"
        className="text-sm text-muted hover:text-accent self-center"
      >
        Forgot password?
      </a>
    </form>
  );
}
