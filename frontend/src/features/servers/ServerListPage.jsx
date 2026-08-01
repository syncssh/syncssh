import { useEffect, useState } from "react";
import { CopyToClipboard } from "react-copy-to-clipboard";
import { getServers, createServer, deleteServer, rotateServerToken, updateServer } from "../../api/org";
import { MainLayout } from "../../layouts/MainLayout";
import { Button } from "../../components/Button";
import { Input } from "../../components/Input";
import { Card } from "../../components/Card";
import { Badge, Dot } from "../../components/Badge";
import { PageHeader } from "../../components/PageHeader";
import { ListSkeleton } from "../../components/Skeleton";
import { EmptyState } from "../../components/EmptyState";
import { useAuth } from "../../context/AuthContext";
import { toast } from "../../components/Toast";
import { useConfirm } from "../../components/ConfirmDialog";
import { ServersIcon } from "../../components/icons";

const _installBase = () =>
  import.meta.env.VITE_INSTALL_BASE_URL ||
  (typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.host}`
    : "");
const buildInstallCommand = (rawToken) =>
  `curl -sL ${_installBase()}/api/v1/install/${rawToken}/ | bash`;

// Sync heartbeat: cron polls once a minute, so anything older than ~3 min is
// suspicious. Render as a colored chip next to the Active badge so admins
// can spot a wedged agent at a glance instead of having to dig into logs.
const SYNC_STALE_MS = 3 * 60 * 1000;

function syncStatus(lastSyncedAt, clockOffsetMs = 0) {
  if (!lastSyncedAt) return { label: "Never synced", tone: "neutral" };
  // Project the local clock onto the server's timeline (clockOffsetMs =
  // localNow − serverNow at fetch) so a skewed device clock can't make a
  // freshly-synced server look stale. The offset cancels in this delta.
  const age = Date.now() - clockOffsetMs - new Date(lastSyncedAt).getTime();
  const ago = formatAgo(age);
  if (age > SYNC_STALE_MS) {
    return { label: `Stale — last sync ${ago}`, tone: "warn" };
  }
  return { label: `Synced ${ago}`, tone: "accent" };
}

function formatAgo(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 15) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function ServerListPage() {
  const { role } = useAuth();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const confirm = useConfirm();

  const [servers, setServers] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", ip_address: "", ssh_user: "" });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  // Bumped on a timer so the relative-time chips ("Synced 12s ago") tick
  // forward while the page sits open, without re-fetching every second.
  const [, setNowTick] = useState(0);

  // Shows the install command + raw token exactly once, immediately after
  // create or rotate. Cleared on dismiss — no way to recover the token after.
  const [secretReveal, setSecretReveal] = useState(null); // { serverName, rawToken }

  // localNow − serverNow at the moment of the last fetch. Used to render sync
  // age against the server's clock instead of the (possibly skewed) device one.
  // Kept in state (not a ref) so it's read cleanly during render — every load
  // re-renders anyway via setServers.
  const [clockOffset, setClockOffset] = useState(0);

  const load = () =>
    getServers().then((r) => {
      if (r.data.now) {
        setClockOffset(Date.now() - new Date(r.data.now).getTime());
      }
      setServers(r.data.servers);
      setLoading(false);
    });

  useEffect(() => {
    load();
  }, []);

  // Keep last_synced_at fresh so an admin can watch a key change land instead
  // of guessing. syncssh is pull-only — we can't force the agent to sync, but
  // the agent pulls every ~60s, so re-fetching surfaces the new timestamp as
  // soon as it does. Poll only while the tab is visible (battery), and bump a
  // tick every 10s so the "x ago" labels stay honest between fetches.
  useEffect(() => {
    const fetchIfVisible = () => {
      if (document.visibilityState === "visible") load();
    };
    const dataTimer = setInterval(fetchIfVisible, 30000);
    const tickTimer = setInterval(() => setNowTick((n) => n + 1), 10000);
    document.addEventListener("visibilitychange", fetchIfVisible);
    return () => {
      clearInterval(dataTimer);
      clearInterval(tickTimer);
      document.removeEventListener("visibilitychange", fetchIfVisible);
    };
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await load();
      toast("Sync status refreshed");
    } finally {
      setRefreshing(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const res = await createServer(form);
      setForm({ name: "", ip_address: "", ssh_user: "" });
      setShowForm(false);
      setSecretReveal({ serverName: res.data.name, rawToken: res.data.token });
      load();
    } catch (err) {
      toast(err.response?.data?.error || "Failed to create server", { type: "error" });
    }
  };

  const handleDelete = async (server) => {
    if (
      !(await confirm({
        title: "Remove server",
        message: `Remove ${server.name}? The agent stops being managed and its keys are no longer synced.`,
        confirmLabel: "Remove",
        danger: true,
      }))
    )
      return;
    await deleteServer(server.id);
    load();
  };

  const handleToggleSelfService = async (server) => {
    try {
      await updateServer(server.id, { allow_self_service: !server.allow_self_service });
      load();
    } catch (err) {
      toast(err.response?.data?.error || "Update failed", { type: "error" });
    }
  };

  const handleRotate = async (server) => {
    if (
      !(await confirm({
        title: "Rotate token",
        message: `Rotate the token for ${server.name}? The current agent will stop syncing until you re-run the install command.`,
        confirmLabel: "Rotate",
        danger: true,
      }))
    )
      return;
    try {
      const res = await rotateServerToken(server.id);
      setSecretReveal({ serverName: server.name, rawToken: res.data.token });
      load();
    } catch (err) {
      toast(err.response?.data?.error || "Rotation failed", { type: "error" });
    }
  };

  const onCopy = () => toast("Install command copied!");

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <PageHeader
          title="Servers"
          subtitle="Manage and monitor server agents. Keys are automatically synchronized across all active nodes."
          action={
            isAdmin && (
              <Button variant={showForm ? "secondary" : "primary"} onClick={() => setShowForm(!showForm)}>
                {showForm ? "Cancel" : "+ Add server"}
              </Button>
            )
          }
        />

        {showForm && isAdmin && (
          <form
            onSubmit={handleCreate}
            className="bg-surface border border-line rounded-lg p-4 sm:p-6 mb-6 space-y-4"
          >
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <Input
                label="Name"
                placeholder="prod-api-01"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
              />
              <Input
                label="IP Address"
                placeholder="192.168.1.100"
                value={form.ip_address}
                onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
                required
              />
              <Input
                label="SSH User"
                placeholder="ubuntu"
                value={form.ssh_user}
                onChange={(e) => setForm({ ...form, ssh_user: e.target.value })}
                required
              />
            </div>
            <div className="flex justify-end">
              <Button type="submit">Create server</Button>
            </div>
          </form>
        )}

        {loading ? (
          <ListSkeleton />
        ) : servers.length === 0 ? (
          <EmptyState
            icon={<ServersIcon className="w-9 h-9" />}
            title="No servers registered"
            hint={
              isAdmin
                ? "Register a server and install the agent to begin synchronization."
                : "No servers have been registered in this workspace yet."
            }
            action={
              isAdmin && !showForm ? (
                <Button onClick={() => setShowForm(true)}>+ Add server</Button>
              ) : null
            }
          />
        ) : (
          <div className="space-y-3">
            {servers.map((s) => {
              const sync = syncStatus(s.last_synced_at, clockOffset);
              return (
                <Card key={s.id} className="p-4">
                  {/* Header row: name + active LED, always side by side */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-mono font-medium text-ink truncate">{s.name}</p>
                      {/* ip_address + ssh_user are admin-only in the API payload */}
                      {isAdmin && (
                        <p className="text-sm text-muted font-mono truncate">
                          {s.ip_address} · {s.ssh_user}
                        </p>
                      )}
                    </div>
                    <Badge tone={s.is_active ? "accent" : "danger"} className="shrink-0">
                      <Dot tone={s.is_active ? "accent" : "danger"} glow={s.is_active} />
                      {s.is_active ? "Active" : "Inactive"}
                    </Badge>
                  </div>

                  {/* Sync heartbeat line with the manual refresh control */}
                  <div className="flex items-center gap-2 mt-3 text-sm font-mono">
                    <Dot tone={sync.tone} glow={sync.tone === "accent"} />
                    <span
                      className={
                        sync.tone === "warn"
                          ? "text-warn"
                          : sync.tone === "accent"
                          ? "text-accent"
                          : "text-muted"
                      }
                      title={s.last_synced_at ? new Date(s.last_synced_at).toLocaleString() : "Agent has never polled"}
                    >
                      {sync.label}
                    </span>
                    <button
                      onClick={handleRefresh}
                      disabled={refreshing}
                      title="Refresh sync status (agents pull every ~60s)"
                      aria-label="Refresh sync status"
                      className="text-faint hover:text-ink disabled:opacity-50 cursor-pointer ml-0.5"
                    >
                      <svg
                        className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`}
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <path d="M21 2v6h-6" />
                        <path d="M3 12a9 9 0 0 1 15-6.7L21 8" />
                        <path d="M3 22v-6h6" />
                        <path d="M21 12a9 9 0 0 1-15 6.7L3 16" />
                      </svg>
                    </button>
                  </div>

                  {/* Admin controls — separated, wrap freely on small screens */}
                  {isAdmin && (
                    <div className="mt-4 pt-4 border-t border-line-soft flex flex-wrap items-center gap-x-5 gap-y-3">
                      {s.token_prefix && (
                        <span className="text-xs text-faint font-mono">
                          token{" "}
                          <code className="bg-raised border border-line px-1.5 py-0.5 rounded text-muted">
                            {s.token_prefix}…
                          </code>
                        </span>
                      )}
                      <button
                        onClick={() => handleRotate(s)}
                        className="text-xs font-mono text-accent hover:underline cursor-pointer"
                      >
                        Rotate token & get install command
                      </button>
                      <label className="text-xs text-muted flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={!!s.allow_self_service}
                          onChange={() => handleToggleSelfService(s)}
                        />
                        Allow developers to self-deploy here
                      </label>
                      <Button
                        variant="danger"
                        onClick={() => handleDelete(s)}
                        className="ml-auto"
                      >
                        Remove
                      </Button>
                    </div>
                  )}
                </Card>
              );
            })}
          </div>
        )}

        {secretReveal && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <Card className="max-w-2xl w-full p-6 shadow-2xl">
              <h2 className="text-lg font-semibold font-mono text-ink mb-2">
                Install command for {secretReveal.serverName}
              </h2>
              <p className="text-sm text-muted mb-4">
                This token is shown <strong className="text-ink">only once</strong>. Copy the command
                below and run it on the target server now. If you lose it, you
                will need to rotate the token again.
              </p>
              <pre className="bg-base border border-line text-accent text-xs p-3 rounded overflow-x-auto whitespace-pre-wrap break-all">
                {buildInstallCommand(secretReveal.rawToken)}
              </pre>
              <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-3 mt-4">
                <Button variant="secondary" onClick={() => setSecretReveal(null)}>
                  Close
                </Button>
                <CopyToClipboard
                  text={buildInstallCommand(secretReveal.rawToken)}
                  onCopy={onCopy}
                >
                  <Button>Copy command</Button>
                </CopyToClipboard>
              </div>
            </Card>
          </div>
        )}
      </div>
    </MainLayout>
  );
}
