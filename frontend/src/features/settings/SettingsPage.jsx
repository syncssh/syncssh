import { useEffect, useState } from "react";
import { changePassword } from "../../api/auth";
import { MainLayout } from "../../layouts/MainLayout";
import { Button } from "../../components/Button";
import { Input } from "../../components/Input";
import { Card } from "../../components/Card";
import { PageHeader } from "../../components/PageHeader";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { toast } from "../../components/Toast";
import { Avatar } from "../../components/Avatar";
import { Segmented } from "../../components/Segmented";
import { SettingsTabs } from "./SettingsTabs";
import { getMemberships, leaveMembership } from "../../api/org";
import { useConfirm } from "../../components/ConfirmDialog";

const EMPTY_FORM = { current_password: "", new_password1: "", new_password2: "" };

function ProfileCard({ user }) {
  return (
    <Card className="p-5">
      <h2 className="font-mono text-sm uppercase tracking-wider text-muted mb-4">Profile</h2>
      <div className="flex items-center gap-3">
        <Avatar username={user?.username} email={user?.email} className="w-12 h-12" />
        <div className="min-w-0 leading-tight">
          <p className="font-mono text-sm text-ink truncate">{user?.username}</p>
          <p className="text-sm text-muted truncate">{user?.email}</p>
        </div>
      </div>
    </Card>
  );
}

function AppearanceCard() {
  const { theme, setTheme } = useTheme();
  return (
    <Card className="p-5">
      <h2 className="font-mono text-sm uppercase tracking-wider text-muted mb-1">Appearance</h2>
      <p className="text-sm text-muted mb-4">
        Saved to your account, so it follows you across browsers and devices.
      </p>
      <Segmented
        value={theme}
        onChange={setTheme}
        options={[
          { value: "light", label: "Light" },
          { value: "dark", label: "Dark" },
        ]}
      />
    </Card>
  );
}

export function SettingsPage() {
  const { user, role } = useAuth();
  const confirm = useConfirm();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const [memberships, setMemberships] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e.target.value }));

  const loadMemberships = () => {
    getMemberships().then((response) => {
      setMemberships(response.data.memberships.filter((membership) => !membership.is_personal));
    }).catch(() => {});
  };

  useEffect(() => { loadMemberships(); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (form.new_password1 !== form.new_password2) {
      setError("New passwords do not match");
      return;
    }
    setSaving(true);
    try {
      await changePassword(form);
      setForm(EMPTY_FORM);
      toast("Password changed");
    } catch (err) {
      setError(err.response?.data?.error || "Failed to change password");
    } finally {
      setSaving(false);
    }
  };

  const handleLeave = async (membership) => {
    const ok = await confirm({
      title: `Leave ${membership.organization.name}?`,
      message: `Leave ${membership.organization.name}? Your public keys in this organization will be removed from its servers.`,
      confirmLabel: "Leave organization",
      danger: true,
    });
    if (!ok) return;
    try {
      await leaveMembership(membership.organization.id);
      loadMemberships();
      toast(`Left ${membership.organization.name}`);
    } catch (err) {
      toast(err.response?.data?.error || "Could not leave this organization", { type: "error" });
    }
  };

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <PageHeader
          title="Settings"
          subtitle={isAdmin ? "Your account and workspace preferences." : "Your account preferences."}
        />
        <SettingsTabs />

        <div className="space-y-4">
          <ProfileCard user={user} />
          <AppearanceCard />

          {memberships.length > 0 && (
            <Card className="p-5">
              <h2 className="font-mono text-sm uppercase tracking-wider text-muted mb-1">Organizations you belong to</h2>
              <p className="text-sm text-muted mb-4">
                These are separate from your own workspace. You can leave an organization at any time.
              </p>
              <div className="space-y-3">
                {memberships.map((membership) => (
                  <div key={membership.organization.id} className="flex flex-wrap items-center justify-between gap-3 rounded border border-line p-3">
                    <div>
                      <p className="font-mono text-sm text-ink">{membership.organization.name}</p>
                      <p className="font-mono text-xs uppercase tracking-wide text-faint">{membership.role}</p>
                    </div>
                    <Button variant="danger" className="px-2.5 py-1 text-xs" onClick={() => handleLeave(membership)}>
                      Leave
                    </Button>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <Card className="p-5">
            <h2 className="font-mono text-sm uppercase tracking-wider text-muted mb-1">
              Change password
            </h2>
            <p className="text-sm text-muted mb-4">
              Signed in as <span className="text-ink font-mono">{user?.username}</span>.
              Changing your password signs out every other session.
            </p>
            <form onSubmit={handleSubmit} className="flex flex-col gap-4 max-w-md">
              <Input
                label="Current password"
                type="password"
                autoComplete="current-password"
                value={form.current_password}
                onChange={set("current_password")}
                required
              />
              <Input
                label="New password"
                type="password"
                autoComplete="new-password"
                value={form.new_password1}
                onChange={set("new_password1")}
                required
              />
              <Input
                label="Repeat new password"
                type="password"
                autoComplete="new-password"
                value={form.new_password2}
                onChange={set("new_password2")}
                error={error}
                required
              />
              <div>
                <Button type="submit" loading={saving}>
                  Change password
                </Button>
              </div>
            </form>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}
