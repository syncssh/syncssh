import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { getOrg, removeMember } from "../../api/org";
import { MainLayout } from "../../layouts/MainLayout";
import { Card } from "../../components/Card";
import { Badge } from "../../components/Badge";
import { Skeleton, TableSkeleton } from "../../components/Skeleton";
import { Button } from "../../components/Button";
import { useAuth } from "../../context/AuthContext";
import { useConfirm } from "../../components/ConfirmDialog";
import { toast } from "../../components/Toast";

const ROLE_TONE = { OWNER: "violet", ADMIN: "info" };

export function DashboardPage() {
  const [data, setData] = useState(null);
  const [removingId, setRemovingId] = useState(null);
  const { user } = useAuth();
  const confirm = useConfirm();
  const location = useLocation();

  const load = () => getOrg().then((res) => setData(res.data)).catch(() => {});

  useEffect(() => { load(); }, []);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    if (params.get("invite") !== "accepted") return;
    const organization = params.get("organization");
    toast(organization ? `You joined ${organization}` : "Invitation accepted");
    // Do not leave a success marker in history: navigating back should not
    // repeatedly show the invitation notification.
    window.history.replaceState({}, "", location.pathname);
  }, [location.pathname, location.search]);

  if (!data)
    return (
      <MainLayout>
        <div className="max-w-6xl mx-auto" aria-hidden="true">
          <div className="mb-8 space-y-2">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-8 w-1/2" />
            <Skeleton className="h-3 w-2/3" />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-10">
            {Array.from({ length: 3 }).map((_, i) => (
              <Card key={i} className="p-5 space-y-3">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-8 w-12" />
              </Card>
            ))}
          </div>
          <Skeleton className="h-3 w-32 mb-3" />
          <TableSkeleton rows={4} cols={3} />
        </div>
      </MainLayout>
    );

  // Backend only includes member emails for admins; hide the column otherwise
  // so non-admins don't see an empty Email column.
  const isAdmin = data.your_role === "OWNER" || data.your_role === "ADMIN";
  const isOwner = data.your_role === "OWNER";

  const handleRemove = async (member) => {
    const ok = await confirm({
      title: "Remove member",
      message: `Remove ${member.username} from this workspace? Their public keys in this workspace will be removed from its servers.`,
      confirmLabel: "Remove member",
      danger: true,
    });
    if (!ok) return;
    setRemovingId(member.id);
    try {
      await removeMember(member.id);
      await load();
      toast(`${member.username} removed from workspace`);
    } catch (err) {
      toast(err.response?.data?.error || "Could not remove member", { type: "error" });
    } finally {
      setRemovingId(null);
    }
  };

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <div className="mb-8">
          <p className="font-mono text-xs uppercase tracking-widest text-faint mb-1">
            Organization
          </p>
          <h1 className="text-3xl font-semibold text-ink font-mono">{data.org.name}</h1>
          <p className="text-muted mt-2 text-sm">
            Manage team members, servers, and active SSH keys.
          </p>
        </div>

        {/* Stats — stack on phones, three across once there's room. */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-10">
          <StatCard label="Members" value={data.members.length} />
          <StatCard label="Servers" value={data.server_count ?? "—"} to="/servers" />
          <StatCard label="Active keys" value={data.key_count ?? "—"} to="/pubkeys" />
        </div>

        {/* Members */}
        <div>
          <h2 className="text-sm font-mono uppercase tracking-wider text-muted mb-3">
            Team members
          </h2>
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[32rem]">
                <thead className="border-b border-line">
                  <tr className="text-left font-mono text-xs uppercase tracking-wider text-faint">
                    <th className="px-4 py-3 font-medium">User</th>
                    {isAdmin && <th className="px-4 py-3 font-medium">Email</th>}
                    <th className="px-4 py-3 font-medium">Role</th>
                    {isOwner && <th className="px-4 py-3 font-medium text-right">Action</th>}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {data.members.map((m) => (
                    <tr key={m.id} className="hover:bg-raised/40">
                      <td className="px-4 py-3 font-medium text-ink font-mono">{m.username}</td>
                      {isAdmin && <td className="px-4 py-3 text-muted">{m.email}</td>}
                      <td className="px-4 py-3">
                        <Badge tone={ROLE_TONE[m.role] ?? "neutral"}>{m.role}</Badge>
                      </td>
                      {isOwner && (
                        <td className="px-4 py-3 text-right">
                          {m.id !== user?.id && (
                            <Button
                              variant="danger"
                              className="px-2.5 py-1 text-xs"
                              onClick={() => handleRemove(m)}
                              loading={removingId === m.id}
                            >
                              Remove
                            </Button>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}

function StatCard({ label, value, to }) {
  const body = (
    <>
      <p className="text-xs font-mono uppercase tracking-wider text-muted mb-2">{label}</p>
      <p className="text-3xl font-semibold text-ink font-mono tabular-nums">{value}</p>
    </>
  );

  if (!to) return <Card className="p-5">{body}</Card>;

  return (
    <Link to={to} className="group block rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
      <Card className="p-5 relative transition-colors group-hover:border-accent/50">
        {body}
        <span
          aria-hidden="true"
          className="absolute top-5 right-5 font-mono text-faint transition-colors group-hover:text-accent"
        >
          →
        </span>
      </Card>
    </Link>
  );
}
