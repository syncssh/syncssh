import { useEffect, useState } from "react";
import { getAuditLog } from "../../api/audit";
import { MainLayout } from "../../layouts/MainLayout";
import { Button } from "../../components/Button";
import { Input } from "../../components/Input";
import { Card } from "../../components/Card";
import { Badge } from "../../components/Badge";
import { PageHeader } from "../../components/PageHeader";
import { TableSkeleton } from "../../components/Skeleton";
import { EmptyState } from "../../components/EmptyState";
import { useAuth } from "../../context/AuthContext";

// Map each event family to a tone from the shared palette so the log reads at
// a glance — server events emerald, key events violet, auth blue, and so on.
const ACTION_TONES = {
  auth: "info",
  publickey: "violet",
  server: "accent",
  apikey: "warn",
  organizationmembership: "danger",
  organizationinvite: "info",
  invite: "info",
};

function actionTone(action) {
  return ACTION_TONES[action.split(".")[0]] || "neutral";
}

function formatTimestamp(iso) {
  const d = new Date(iso);
  return d.toLocaleString();
}

export function AuditLogPage() {
  const { role } = useAuth();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ action: "", actor: "", limit: 50 });

  const load = () => {
    setLoading(true);
    const params = {};
    if (filters.action) params.action = filters.action;
    if (filters.actor) params.actor = filters.actor;
    params.limit = filters.limit;
    getAuditLog(params)
      .then((r) => {
        setEvents(r.data.events);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    if (isAdmin) load();
    else setLoading(false);
    // Filters are submitted explicitly; changing a field must not auto-fetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  const handleFilter = (e) => {
    e.preventDefault();
    load();
  };

  const handleReset = () => {
    setFilters({ action: "", actor: "", limit: 50 });
    setTimeout(load, 0);
  };

  if (!isAdmin) {
    return (
      <MainLayout>
        <div className="max-w-6xl mx-auto">
          <PageHeader title="Audit Log" />
          <Card className="p-12 text-center text-muted">
            Only Owners and Admins can view the audit log.
          </Card>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <PageHeader
          title="Audit Log"
          subtitle="An append-only record of all actions and events within this organization."
          action={
            <Button variant="secondary" onClick={load} loading={loading}>
              Refresh
            </Button>
          }
        />

        <form
          onSubmit={handleFilter}
          className="bg-surface border border-line rounded-lg p-4 mb-6 flex gap-3 items-end flex-wrap"
        >
          <Input
            label="Action"
            placeholder="e.g. server.token_rotated"
            value={filters.action}
            onChange={(e) => setFilters({ ...filters, action: e.target.value })}
            className="flex-1 min-w-[200px]"
          />
          <Input
            label="Actor (username)"
            placeholder="e.g. admin"
            value={filters.actor}
            onChange={(e) => setFilters({ ...filters, actor: e.target.value })}
            className="flex-1 min-w-[180px]"
          />
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-mono uppercase tracking-wider text-muted">Limit</label>
            <select
              value={filters.limit}
              onChange={(e) =>
                setFilters({ ...filters, limit: Number(e.target.value) })
              }
              className="bg-base border border-line rounded px-3 py-2 text-sm text-ink h-[38px] focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent/50"
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </div>
          <Button type="submit" loading={loading}>Apply</Button>
          <Button type="button" variant="secondary" onClick={handleReset} disabled={loading}>
            Reset
          </Button>
        </form>

        {loading ? (
          <TableSkeleton rows={8} cols={5} />
        ) : events.length === 0 ? (
          <EmptyState
            icon="≣"
            title="No events match the current filters"
            hint="Try clearing the action or actor filter, or raising the limit."
            action={
              <Button variant="secondary" onClick={handleReset}>
                Reset filters
              </Button>
            }
          />
        ) : (
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[40rem]">
              <thead className="text-left border-b border-line">
                <tr className="font-mono text-xs uppercase tracking-wider text-faint">
                  <th className="px-4 py-3 font-medium">When</th>
                  <th className="px-4 py-3 font-medium">Actor</th>
                  <th className="px-4 py-3 font-medium">Action</th>
                  <th className="px-4 py-3 font-medium min-w-[8rem]">Target</th>
                  <th className="px-4 py-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {events.map((e, index) => (
                  <tr key={`${e.created_at}-${e.action}-${index}`} className="hover:bg-raised/40">
                    <td className="px-4 py-3 text-muted font-mono whitespace-nowrap">
                      {formatTimestamp(e.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      {e.actor_username ? (
                        <span className="font-medium text-ink font-mono">
                          {e.actor_username}
                        </span>
                      ) : (
                        <span className="text-faint italic font-mono">
                          {e.actor_kind}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <Badge tone={actionTone(e.action)}>{e.action}</Badge>
                    </td>
                    <td className="px-4 py-3 text-muted whitespace-nowrap">
                      {e.target ? (
                        <code className="text-xs bg-raised border border-line px-1.5 py-0.5 rounded whitespace-nowrap">
                          {e.target}
                        </code>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">
                      {Object.keys(e.metadata || {}).length === 0 ? (
                        <span className="text-faint">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(e.metadata).map(([k, v]) => (
                            <span
                              key={k}
                              className="bg-raised border border-line px-1.5 py-0.5 rounded font-mono"
                            >
                              <span className="text-faint">{k}:</span>{" "}
                              <span className="text-ink">
                                {typeof v === "object" ? JSON.stringify(v) : String(v)}
                              </span>
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            <div className="px-4 py-3 border-t border-line text-xs text-faint font-mono">
              Showing {events.length} event{events.length === 1 ? "" : "s"}
              {events.length === filters.limit && " (raise limit to see more)"}
            </div>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
