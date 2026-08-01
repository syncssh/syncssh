import { useEffect, useState } from "react";
import { CopyToClipboard } from "react-copy-to-clipboard";
import {
  getOrg,
  updateOrg,
  getWebhook,
  saveWebhook,
  patchWebhook,
  rotateWebhookSecret,
  sendTestWebhook,
  deleteWebhook,
} from "../../api/org";
import { MainLayout } from "../../layouts/MainLayout";
import { Button } from "../../components/Button";
import { Input } from "../../components/Input";
import { Card } from "../../components/Card";
import { Badge } from "../../components/Badge";
import { PageHeader } from "../../components/PageHeader";
import { Skeleton } from "../../components/Skeleton";
import { EmptyState } from "../../components/EmptyState";
import { Toggle } from "../../components/Toggle";
import { Segmented } from "../../components/Segmented";
import { useAuth } from "../../context/AuthContext";
import { toast } from "../../components/Toast";
import { useConfirm } from "../../components/ConfirmDialog";
import { SettingsTabs } from "./SettingsTabs";

const WEBHOOK_EVENTS = [
  "publickey.created",
  "publickey.deleted",
  "publickey.toggled",
  "server.token_rotated",
];

function CardHeading({ children }) {
  return (
    <h2 className="font-mono text-sm uppercase tracking-wider text-muted mb-1">{children}</h2>
  );
}

function WorkspaceNameCard({ org, onRenamed }) {
  const [name, setName] = useState(org.name);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const dirty = name.trim() !== org.name;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      const res = await updateOrg({ name: name.trim() });
      onRenamed(res.data.org);
      toast("Workspace renamed");
    } catch (err) {
      setError(err.response?.data?.error || "Failed to rename workspace");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="p-5">
      <CardHeading>Workspace name</CardHeading>
      <p className="text-sm text-muted mb-4">
        Shown across the app and in invite emails. The workspace identifier{" "}
        <code className="font-mono text-ink">{org.slug}</code> never changes.
      </p>
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row sm:items-start gap-3 max-w-md">
        <div className="flex-1">
          <Input
            aria-label="Workspace name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            error={error}
            required
            maxLength={255}
          />
        </div>
        <Button type="submit" loading={saving} disabled={!dirty || !name.trim()}>
          Save
        </Button>
      </form>
    </Card>
  );
}

function InviteEmailCard({ org, onChanged }) {
  const [saving, setSaving] = useState(false);

  const handleChange = async (theme) => {
    setSaving(true);
    try {
      const res = await updateOrg({ invite_email_theme: theme });
      onChanged(res.data.org);
      toast(`Invite emails will use the ${theme} template`);
    } catch (err) {
      toast(err.response?.data?.error || "Update failed", { type: "error" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="p-5">
      <CardHeading>Invite emails</CardHeading>
      <p className="text-sm text-muted mb-4">
        Color scheme for the invitation emails sent to new members.
      </p>
      <Segmented
        value={org.invite_email_theme}
        onChange={handleChange}
        disabled={saving}
        options={[
          { value: "light", label: "Light" },
          { value: "dark", label: "Dark" },
        ]}
      />
    </Card>
  );
}

// Shown exactly once, immediately after save or rotate — the API never
// returns the secret again. Mirrors the server install-command reveal.
function SecretRevealModal({ secret, onClose }) {
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <Card className="max-w-2xl w-full p-6 shadow-2xl">
        <h2 className="text-lg font-semibold font-mono text-ink mb-2">Webhook signing secret</h2>
        <p className="text-sm text-muted mb-4">
          This secret is shown <strong className="text-ink">only once</strong>. Store it in your
          receiver now — if you lose it, rotate the secret to get a new one.
        </p>
        <pre className="bg-base border border-line text-accent text-xs p-3 rounded overflow-x-auto whitespace-pre-wrap break-all">
          {secret}
        </pre>
        <p className="text-sm text-muted mt-4">
          Verify each delivery by computing HMAC-SHA256 of the raw request body with this secret
          and comparing it to the{" "}
          <code className="font-mono text-ink">X-SyncSSH-Signature</code> header
          (<code className="font-mono text-ink">sha256=&lt;hex&gt;</code>).
        </p>
        <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-3 mt-4">
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          <CopyToClipboard text={secret} onCopy={() => toast("Secret copied!")}>
            <Button>Copy secret</Button>
          </CopyToClipboard>
        </div>
      </Card>
    </div>
  );
}

function WebhookCard() {
  const confirm = useConfirm();
  const [loading, setLoading] = useState(true);
  // null when not configured; {url, is_active, created_at} when configured.
  const [webhook, setWebhook] = useState(null);
  const [url, setUrl] = useState("");
  const [urlError, setUrlError] = useState(null);
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState(false);
  const [secret, setSecret] = useState(null);

  useEffect(() => {
    getWebhook()
      .then((res) => {
        if (res.data.configured) {
          setWebhook(res.data);
          setUrl(res.data.url);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const configured = !!webhook;
  const dirty = configured && url.trim() !== webhook.url;

  const handleSave = async (e) => {
    e.preventDefault();
    setUrlError(null);
    if (configured && dirty) {
      const ok = await confirm({
        title: "Change webhook URL",
        message:
          "Saving a new URL generates a new signing secret. Your receiver must be updated with the secret shown after saving.",
        confirmLabel: "Save & get new secret",
      });
      if (!ok) return;
    }
    setSaving(true);
    try {
      const res = await saveWebhook({ url: url.trim() });
      setWebhook(res.data);
      setUrl(res.data.url);
      setSecret(res.data.secret);
    } catch (err) {
      setUrlError(err.response?.data?.error || "Failed to save webhook");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async () => {
    setBusy(true);
    try {
      const res = await patchWebhook({ is_active: !webhook.is_active });
      setWebhook(res.data);
      toast(res.data.is_active ? "Webhook resumed" : "Webhook paused");
    } catch (err) {
      toast(err.response?.data?.error || "Update failed", { type: "error" });
    } finally {
      setBusy(false);
    }
  };

  const handleTest = async () => {
    setBusy(true);
    try {
      await sendTestWebhook();
      toast("Test event queued — check your receiver");
    } catch (err) {
      toast(err.response?.data?.error || "Failed to queue test event", { type: "error" });
    } finally {
      setBusy(false);
    }
  };

  const handleRotate = async () => {
    const ok = await confirm({
      title: "Rotate signing secret",
      message:
        "Deliveries signed with the current secret will stop verifying. Update your receiver with the new secret shown after rotating.",
      confirmLabel: "Rotate",
      danger: true,
    });
    if (!ok) return;
    setBusy(true);
    try {
      const res = await rotateWebhookSecret();
      setSecret(res.data.secret);
    } catch (err) {
      toast(err.response?.data?.error || "Rotation failed", { type: "error" });
    } finally {
      setBusy(false);
    }
  };

  const handleRemove = async () => {
    const ok = await confirm({
      title: "Remove webhook",
      message: "Security notifications stop being delivered. The signing secret is discarded.",
      confirmLabel: "Remove",
      danger: true,
    });
    if (!ok) return;
    setBusy(true);
    try {
      await deleteWebhook();
      setWebhook(null);
      setUrl("");
      toast("Webhook removed");
    } catch (err) {
      toast(err.response?.data?.error || "Failed to remove webhook", { type: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <CardHeading>Security notifications</CardHeading>
          <p className="text-sm text-muted mb-4 max-w-xl">
            POST security events to an HTTPS endpoint you control, signed so your receiver can
            verify they came from SyncSSH. Events sent:
          </p>
        </div>
        {configured && (
          <Badge tone={webhook.is_active ? "accent" : "neutral"} className="shrink-0">
            {webhook.is_active ? "Active" : "Paused"}
          </Badge>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-5">
        {WEBHOOK_EVENTS.map((ev) => (
          <code
            key={ev}
            className="font-mono text-xs text-muted bg-raised border border-line px-1.5 py-0.5 rounded"
          >
            {ev}
          </code>
        ))}
      </div>

      {loading ? (
        <div className="space-y-3 max-w-xl" aria-hidden="true">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-40" />
        </div>
      ) : (
        <>
          <form onSubmit={handleSave} className="flex flex-col sm:flex-row sm:items-start gap-3 max-w-xl">
            <div className="flex-1">
              <Input
                aria-label="Webhook URL"
                type="url"
                placeholder="https://hooks.example.com/syncssh"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                error={urlError}
                required
              />
            </div>
            {(!configured || dirty) && (
              <Button type="submit" loading={saving}>
                {configured ? "Save URL" : "Enable webhook"}
              </Button>
            )}
          </form>

          {configured && (
            <div className="mt-4 pt-4 border-t border-line-soft flex flex-wrap items-center gap-x-5 gap-y-3">
              <Toggle
                checked={webhook.is_active}
                onChange={handleToggle}
                disabled={busy}
                label={webhook.is_active ? "Deliveries on" : "Deliveries paused"}
              />
              <button
                onClick={handleTest}
                disabled={busy || !webhook.is_active || dirty}
                title={
                  !webhook.is_active
                    ? "Resume deliveries to send a test event"
                    : dirty
                    ? "Save the URL change first"
                    : "Queue a webhook.test delivery to your endpoint"
                }
                className="text-xs font-mono text-accent hover:underline cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed disabled:no-underline"
              >
                Send test event
              </button>
              <button
                onClick={handleRotate}
                disabled={busy}
                title="Generate a new signing secret (shown once)"
                className="text-xs font-mono text-accent hover:underline cursor-pointer disabled:opacity-50"
              >
                Rotate secret
              </button>
              <span className="text-xs text-faint font-mono">
                configured {new Date(webhook.created_at).toLocaleDateString("en-GB")}
              </span>
              <Button variant="danger" onClick={handleRemove} disabled={busy} className="ml-auto">
                Remove
              </Button>
            </div>
          )}
        </>
      )}

      {secret && <SecretRevealModal secret={secret} onClose={() => setSecret(null)} />}
    </Card>
  );
}

export function WorkspaceSettingsPage() {
  const { role, features } = useAuth();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const [org, setOrg] = useState(null);

  useEffect(() => {
    if (isAdmin) getOrg().then((res) => setOrg(res.data.org));
  }, [isAdmin]);

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <PageHeader
          title="Settings"
          subtitle={isAdmin ? "Your account and workspace preferences." : "Your account preferences."}
        />
        <SettingsTabs />

        {!isAdmin ? (
          <EmptyState
            icon="⌀"
            title="Workspace settings are managed by owners and admins"
            hint="Ask a workspace owner if something here needs changing."
          />
        ) : !org ? (
          <div className="space-y-4" aria-hidden="true">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-56 w-full" />
          </div>
        ) : (
          <>
            <p className="text-sm text-muted mb-4">
              These settings apply to the{" "}
              <span className="text-ink font-mono">{org.name}</span> workspace.
            </p>
            <div className="space-y-4">
              <WorkspaceNameCard org={org} onRenamed={setOrg} />
              {features.invite_email_theming && <InviteEmailCard org={org} onChanged={setOrg} />}
              {features.webhooks && <WebhookCard />}
            </div>
          </>
        )}
      </div>
    </MainLayout>
  );
}
