import { useEffect, useState } from "react";
import { CopyToClipboard } from "react-copy-to-clipboard";
import client from "../../api/client";
import { MainLayout } from "../../layouts/MainLayout";
import { Button } from "../../components/Button";
import { Input } from "../../components/Input";
import { Card } from "../../components/Card";
import { Badge } from "../../components/Badge";
import { PageHeader } from "../../components/PageHeader";
import { ListSkeleton } from "../../components/Skeleton";
import { EmptyState } from "../../components/EmptyState";
import { MailIcon } from "../../components/icons";
import { useAuth } from "../../context/AuthContext";
import { toast } from "../../components/Toast";

const PAGE_SIZE = 20;

// Tabs mirror the server-side status buckets. "Pending" is first and is the
// default so expired invites don't clutter the initial view.
const STATUS_TABS = [
  { key: "pending", label: "Pending" },
  { key: "accepted", label: "Accepted" },
  { key: "expired", label: "Expired" },
  { key: "all", label: "All" },
];

// Empty-state copy keyed by the active filter, so an empty tab explains itself
// rather than always claiming no invites were ever sent.
const EMPTY_COPY = {
  pending: { title: "No pending invitations", hint: "Invite team members by email to grant them access." },
  accepted: { title: "No accepted invitations", hint: "Accepted invitations will appear here." },
  expired: { title: "No expired invitations", hint: "Expired invitations will appear here." },
  all: { title: "No invitations found", hint: "Invite team members by email to grant them access." },
};

export function InviteListPage() {
  const { role, emailDeliveryConfigured } = useAuth();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const [invites, setInvites] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ email: "", role: "DEVELOPER", sendEmail: true });
  const [newInvite, setNewInvite] = useState(null);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("pending");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [hasNext, setHasNext] = useState(false);
  const [counts, setCounts] = useState(null);

  const load = (nextStatus = status, nextPage = page) => {
    setLoading(true);
    return client
      .get("/invites/", {
        params: { status: nextStatus, page: nextPage, page_size: PAGE_SIZE },
      })
      .then((r) => {
        setInvites(r.data.invites);
        setTotal(r.data.total);
        setHasNext(r.data.has_next);
        setCounts(r.data.counts);
        setLoading(false);
      });
  };

  useEffect(() => {
    if (isAdmin) load(status, page);
    else setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin, status, page]);

  const selectStatus = (key) => {
    if (key === status) return;
    setPage(1);
    setStatus(key);
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const res = await client.post("/invites/", {
        email: form.email,
        role: form.role,
        send_email: form.sendEmail,
      });
      setNewInvite(res.data.invite_url);
      // The backend emails the link directly; surface whether that delivery
      // actually went out so admins know if they need to share it manually.
      if (res.data.email_sent) {
        toast(`Invite emailed to ${res.data.email}`, { type: "success" });
      } else if (res.data.email_skipped) {
        toast("Invite created — copy the link below to share it.", { type: "success" });
      } else {
        toast("Invite created, but the email couldn't be sent — copy the link below to share it manually.", { type: "error" });
      }
      setForm({ email: "", role: "DEVELOPER", sendEmail: true });
      setShowForm(false);
      // A fresh invite is pending, so surface it on the first page of that tab.
      // If we're already there, refetch directly; otherwise let the state change
      // drive the reload (and avoid a double fetch).
      if (status === "pending" && page === 1) load("pending", 1);
      else {
        setStatus("pending");
        setPage(1);
      }
    } catch (err) {
      toast(err.response?.data?.error || "Failed to send invite", { type: "error" });
    }
  };

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <PageHeader
          title="Invites"
          action={
            isAdmin && (
              <Button variant={showForm ? "secondary" : "primary"} onClick={() => setShowForm(!showForm)}>
                {showForm ? "Cancel" : "+ Send invite"}
              </Button>
            )
          }
        />

        {/* Email-delivery warning — invites + signup verification both rely on
            outbound mail. If the backend can't deliver, the link is generated
            but never reaches the recipient's inbox. */}
        {isAdmin && !emailDeliveryConfigured && (
          <div className="bg-warn/10 border border-warn/30 rounded-lg p-4 mb-6">
            <p className="text-sm font-medium text-warn mb-1">
              ⚠ Email delivery isn't configured
            </p>
            <p className="text-sm text-ink/80">
              This instance can't send email, so invited users never receive the
              link and new sign-ups can't confirm their address. Invite links
              shown here still work if you copy and share them manually, but to
              let users self-serve you need an SMTP provider.
            </p>
            <p className="text-sm text-ink/80 mt-2">
              Quick option:{" "}
              <a
                href="https://lettermint.co"
                target="_blank"
                rel="noreferrer"
                className="underline font-medium text-warn"
              >
                Lettermint
              </a>{" "}
              has a free tier — drop its SMTP credentials into{" "}
              <code className="text-xs bg-warn/15 text-warn px-1 rounded">EMAIL_*</code>{" "}
              in your <code className="text-xs bg-warn/15 text-warn px-1 rounded">.env</code>{" "}
              (see <code className="text-xs bg-warn/15 text-warn px-1 rounded">.env.example</code>).
            </p>
          </div>
        )}

        {/* New invite link */}
        {newInvite && (
          <div className="bg-accent/10 border border-accent/30 rounded-lg p-4 mb-6">
            <p className="text-sm font-medium text-accent mb-1">Invite link</p>
            <code className="text-sm break-all text-ink font-mono">{newInvite}</code>
            <div className="flex gap-4 mt-2">
              <CopyToClipboard text={newInvite} onCopy={() => toast("Invite link copied!")}>
                <button className="text-xs font-mono text-accent hover:underline cursor-pointer">Copy link</button>
              </CopyToClipboard>
              <button onClick={() => setNewInvite(null)} className="text-xs font-mono text-muted hover:text-ink cursor-pointer">Dismiss</button>
            </div>
          </div>
        )}

        {showForm && isAdmin && (
          <form onSubmit={handleCreate} className="bg-surface border border-line rounded-lg p-4 sm:p-6 mb-6 flex flex-col gap-4">
            <div className="flex flex-col sm:flex-row gap-4 sm:items-end">
              <Input
                label="Email"
                type="email"
                placeholder="developer@example.com"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                required
                className="flex-1"
              />
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-mono uppercase tracking-wider text-muted">Role</label>
                <select
                  value={form.role}
                  onChange={(e) => setForm({ ...form, role: e.target.value })}
                  className="px-3 py-2 bg-base border border-line rounded text-sm text-ink focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent/50"
                >
                  <option value="DEVELOPER">Developer</option>
                  <option value="ADMIN">Admin</option>
                  <option value="OWNER">Owner</option>
                </select>
              </div>
              <Button type="submit">
                {emailDeliveryConfigured && form.sendEmail ? "Send invite" : "Create invite"}
              </Button>
            </div>
            {/* Opt-out only matters when this instance can actually send email —
                without SMTP the copy-link flow is already the only path. */}
            {emailDeliveryConfigured && (
              <label className="flex items-center gap-2 text-sm text-ink/80 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={!form.sendEmail}
                  onChange={(e) => setForm({ ...form, sendEmail: !e.target.checked })}
                  className="accent-accent"
                />
                Don't send an email — I'll share the link myself
              </label>
            )}
          </form>
        )}

        {!isAdmin ? (
          <Card className="p-12 text-center text-muted">
            Only Owners and Admins can view organization invites.
          </Card>
        ) : (
          <>
            {/* Status filter — expired invites stay out of the default view but
                remain one tab away for audit. Counts come from the server. */}
            <div className="flex flex-wrap gap-1 mb-4 border-b border-line">
              {STATUS_TABS.map((t) => {
                const active = status === t.key;
                const n = counts?.[t.key];
                return (
                  <button
                    key={t.key}
                    onClick={() => selectStatus(t.key)}
                    aria-current={active ? "true" : undefined}
                    className={`px-3 py-2 -mb-px font-mono text-sm border-b-2 transition-colors cursor-pointer ${
                      active
                        ? "border-accent text-ink"
                        : "border-transparent text-muted hover:text-ink"
                    }`}
                  >
                    {t.label}
                    {n != null && (
                      <span className={`ml-1.5 text-xs ${active ? "text-accent" : "text-faint"}`}>
                        {n}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {loading ? (
              <ListSkeleton />
            ) : invites.length === 0 ? (
              <EmptyState
                icon={<MailIcon className="w-9 h-9" />}
                title={(EMPTY_COPY[status] || EMPTY_COPY.all).title}
                hint={
                  isAdmin
                    ? (EMPTY_COPY[status] || EMPTY_COPY.all).hint
                    : "An owner or admin sends invites here."
                }
                action={
                  isAdmin && (status === "pending" || status === "all") && !showForm ? (
                    <Button onClick={() => setShowForm(true)}>+ Send invite</Button>
                  ) : null
                }
              />
            ) : (
              <>
                <div className="space-y-3">
                  {invites.map((i) => {
              // Only pending invites have a useful URL to share. Accepted ones
              // are already done; expired ones would 410 if anyone clicked.
              const isPending = !i.is_accepted && !i.is_expired;
              const mailtoHref = `mailto:${encodeURIComponent(i.email)}` +
                `?subject=${encodeURIComponent("You're invited to join our syncssh org")}` +
                `&body=${encodeURIComponent(`Hi,\n\nYou've been invited to join our syncssh organization. Click this link to accept (it requires logging in with the email this was sent to):\n\n${i.invite_url}\n\nThis invite expires ${new Date(i.expires_at).toLocaleString()}.\n`)}`;
              return (
                <Card key={i.id} className="p-4 flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <p className="font-mono font-medium text-ink truncate">{i.email}</p>
                    <p className="text-xs text-faint font-mono mt-0.5">
                      Role: {i.role} ·{" "}
                      {i.is_accepted
                        ? i.accepted_by
                          ? `accepted by @${i.accepted_by}`
                          : "accepted"
                        : `expires ${new Date(i.expires_at).toLocaleDateString()}`}
                    </p>
                    {isPending && (
                      <div className="flex items-center gap-4 mt-2">
                        <CopyToClipboard text={i.invite_url} onCopy={() => toast("Invite link copied!")}>
                          <button className="text-xs font-mono text-accent hover:underline cursor-pointer">
                            Copy link
                          </button>
                        </CopyToClipboard>
                        <a href={mailtoHref} className="text-xs font-mono text-accent hover:underline">
                          Email it
                        </a>
                      </div>
                    )}
                  </div>
                  <div className="shrink-0">
                    {i.is_accepted ? (
                      <Badge tone="accent">Accepted</Badge>
                    ) : i.is_expired ? (
                      <Badge tone="danger">Expired</Badge>
                    ) : (
                      <Badge tone="warn">Pending</Badge>
                    )}
                  </div>
                </Card>
              );
                  })}
                </div>
                {(page > 1 || hasNext) && (
                  <div className="flex items-center justify-between mt-4">
                    <p className="text-xs text-faint font-mono">
                      Page {page}
                      {total ? ` · ${total} total` : ""}
                    </p>
                    <div className="flex gap-2">
                      <Button
                        variant="secondary"
                        disabled={page <= 1 || loading}
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                      >
                        ← Prev
                      </Button>
                      <Button
                        variant="secondary"
                        disabled={!hasNext || loading}
                        onClick={() => setPage((p) => p + 1)}
                      >
                        Next →
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </div>
    </MainLayout>
  );
}
