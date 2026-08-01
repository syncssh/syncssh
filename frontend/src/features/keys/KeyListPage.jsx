import { useEffect, useState } from "react";
import { getKeys, createKey, deleteKey } from "../../api/keys";
import { MainLayout } from "../../layouts/MainLayout";
import { Button } from "../../components/Button";
import { Input } from "../../components/Input";
import { Card } from "../../components/Card";
import { Badge } from "../../components/Badge";
import { PageHeader } from "../../components/PageHeader";
import { ListSkeleton } from "../../components/Skeleton";
import { EmptyState } from "../../components/EmptyState";
import { useAuth } from "../../context/AuthContext";
import { toast } from "../../components/Toast";
import { useConfirm } from "../../components/ConfirmDialog";

export function KeyListPage() {
  const { role } = useAuth();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const confirm = useConfirm();
  const [keys, setKeys] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", scopes: "read_servers" });
  const [loading, setLoading] = useState(true);
  const [newToken, setNewToken] = useState(null);

  const load = () => getKeys().then((r) => { setKeys(r.data.keys); setLoading(false); }).catch(() => { setLoading(false); });

  useEffect(() => {
    if (isAdmin) load();
    else setLoading(false);
  }, [isAdmin]);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const res = await createKey({ ...form, scopes: form.scopes.split(",") });
      setNewToken(res.data.token);
      setForm({ name: "", scopes: "read_servers" });
      setShowForm(false);
      load();
    } catch (err) {
      toast(err.response?.data?.error || "Failed to create key", { type: "error" });
    }
  };

  const handleDelete = async (id) => {
    if (
      !(await confirm({
        title: "Revoke API key",
        message: "Revoke this key? Anything using it (CI/CD, scripts) will stop working immediately.",
        confirmLabel: "Revoke",
        danger: true,
      }))
    )
      return;
    await deleteKey(id);
    load();
  };

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <PageHeader
          title="API Keys"
          action={
            isAdmin && (
              <Button variant={showForm ? "secondary" : "primary"} onClick={() => setShowForm(!showForm)}>
                {showForm ? "Cancel" : "+ New key"}
              </Button>
            )
          }
        />

        {/* Token shown once */}
        {newToken && (
          <div className="bg-warn/10 border border-warn/30 rounded-lg p-4 mb-6">
            <p className="text-sm font-medium text-warn mb-1">Save your new API key — it will not be shown again:</p>
            <code className="text-sm break-all text-ink font-mono">{newToken}</code>
            <button onClick={() => setNewToken(null)} className="block mt-2 text-xs font-mono text-muted hover:text-ink cursor-pointer">Dismiss</button>
          </div>
        )}

        {showForm && isAdmin && (
          <form onSubmit={handleCreate} className="bg-surface border border-line rounded-lg p-4 sm:p-6 mb-6 flex flex-col sm:flex-row gap-4 sm:items-end">
            <Input
              label="Name"
              placeholder="ci-server-prod"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
              className="flex-1"
            />
            <Input
              label="Scopes (comma-separated)"
              placeholder="read_servers"
              value={form.scopes}
              onChange={(e) => setForm({ ...form, scopes: e.target.value })}
              className="flex-1"
            />
            <Button type="submit">Generate</Button>
          </form>
        )}

        {!isAdmin ? (
          <Card className="p-12 text-center text-muted">
            Only Owners and Admins can view API keys.
          </Card>
        ) : loading ? (
          <ListSkeleton />
        ) : keys.length === 0 ? (
          <EmptyState
            icon="⚿"
            title="No API keys found"
            hint="Generate an API key to enable programmatic access for CI/CD or scripts."
            action={
              isAdmin && !showForm ? (
                <Button onClick={() => setShowForm(true)}>+ New key</Button>
              ) : null
            }
          />
        ) : (
          <div className="space-y-3">
            {keys.map((k) => (
              <Card key={k.id} className="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div className="min-w-0">
                  <p className="font-mono font-medium text-ink">{k.name}</p>
                  <p className="text-xs text-faint font-mono mt-1">prefix <code className="bg-raised border border-line px-1 rounded text-muted">{k.key_prefix}…</code></p>
                  <p className="text-xs text-faint font-mono">scopes: {k.scopes.join(", ")}</p>
                  <p className="text-xs text-faint font-mono">last used: {k.last_used_at ? k.last_used_at : "never"}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <Badge tone={k.is_active ? "accent" : "danger"}>
                    {k.is_active ? "Active" : "Revoked"}
                  </Badge>
                  {isAdmin && <Button variant="danger" onClick={() => handleDelete(k.id)}>Revoke</Button>}
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </MainLayout>
  );
}