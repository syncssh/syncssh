import { useEffect, useState } from "react";
import { getPublicKeys, createPublicKey, deletePublicKey, togglePublicKey, updatePublicKey } from "../../api/pubkeys";
import { getServers } from "../../api/org";
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
import { KeyIcon } from "../../components/icons";

export function PubkeyListPage() {
  const { role } = useAuth();
  const isAdmin = role === "OWNER" || role === "ADMIN";
  const confirm = useConfirm();
  const [keys, setKeys] = useState([]);
  const [servers, setServers] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ key_title: "", key_payload: "", server_ids: [], deploy_to_all: isAdmin });
  const [editingId, setEditingId] = useState(null);
  const [editForm, setEditForm] = useState({ server_ids: [], deploy_to_all: true });
  const [loading, setLoading] = useState(true);

  const load = () => {
    getPublicKeys()
      .then((r) => setKeys(r.data.keys))
      .catch(() => {})
      .finally(() => setLoading(false));
    getServers()
      .then((r) => setServers(r.data.servers))
      .catch(() => {});
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      // Non-admins can never deploy_to_all — backend would 403 anyway.
      const payload = { ...form, deploy_to_all: isAdmin ? form.deploy_to_all : false };
      await createPublicKey(payload);
      setForm({ key_title: "", key_payload: "", server_ids: [], deploy_to_all: isAdmin });
      setShowForm(false);
      load();
    } catch (err) {
      toast(err.response?.data?.error || "Failed to add key", { type: "error" });
    }
  };

  const handleDelete = async (id) => {
    if (
      !(await confirm({
        title: "Remove public key",
        message: "Remove this public key? It will be pulled from the servers it's deployed to on their next sync.",
        confirmLabel: "Remove",
        danger: true,
      }))
    )
      return;
    await deletePublicKey(id);
    load();
  };

  const handleToggle = async (id) => {
    await togglePublicKey(id);
    load();
  };

  const toggleServer = (id, isEdit = false) => {
    const setFn = isEdit ? setEditForm : setForm;
    const ids = isEdit ? editForm.server_ids : form.server_ids;
    setFn((f) => ({
      ...f,
      server_ids: ids.includes(id)
        ? ids.filter((s) => s !== id)
        : [...ids, id],
    }));
  };

  const startEdit = (key) => {
    setEditingId(key.id);
    setEditForm({ server_ids: [...key.assigned_servers], deploy_to_all: key.deploy_to_all });
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditForm({ server_ids: [], deploy_to_all: true });
  };

  const saveEdit = async (keyId) => {
    await updatePublicKey(keyId, { server_ids: editForm.server_ids, deploy_to_all: editForm.deploy_to_all });
    setEditingId(null);
    load();
  };

  const getServerNames = (key) => {
    if (key.deploy_to_all) return "All servers";
    if (!key.assigned_servers || key.assigned_servers.length === 0) return "No servers";
    return servers.filter((s) => key.assigned_servers.includes(s.id)).map((s) => s.name).join(", ");
  };

  return (
    <MainLayout>
      <div className="max-w-6xl mx-auto">
        <PageHeader
          title="Public Keys"
          subtitle={
            isAdmin
              ? "All SSH public keys deployed across this organization"
              : "Your SSH public keys deployed to servers"
          }
          action={
            <Button variant={showForm ? "secondary" : "primary"} onClick={() => setShowForm(!showForm)}>
              {showForm ? "Cancel" : "+ Add key"}
            </Button>
          }
        />

        {showForm && (
          <form onSubmit={handleCreate} className="bg-surface border border-line rounded-lg p-4 sm:p-6 mb-6 space-y-4">
            <Input
              label="Key Title"
              placeholder="Personal MacBook"
              value={form.key_title}
              onChange={(e) => setForm({ ...form, key_title: e.target.value })}
              required
            />
            <div>
              <label className="text-xs font-mono uppercase tracking-wider text-muted block mb-1.5">
                Public Key (openssh format)
              </label>
              <textarea
                rows={4}
                placeholder="ssh-ed25519 AAAA…"
                value={form.key_payload}
                onChange={(e) => setForm({ ...form, key_payload: e.target.value })}
                required
                className="w-full px-3 py-2 bg-base border border-line rounded focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent/50 font-mono text-sm text-ink placeholder:text-faint"
              />
            </div>
            {servers.length > 0 && (() => {
              const pickable = isAdmin ? servers : servers.filter((s) => s.allow_self_service);
              return (
                <div>
                  <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mb-3">
                    {/* Only admins may pick "all servers" — devs would bypass the self-service lock. */}
                    {isAdmin && (
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="deploy_to_all"
                          checked={form.deploy_to_all}
                          onChange={() => setForm((f) => ({ ...f, deploy_to_all: true, server_ids: [] }))}
                        />
                        <span className="text-sm text-ink">Deploy to all servers</span>
                      </label>
                    )}
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="deploy_to_all"
                        checked={!form.deploy_to_all}
                        onChange={() => setForm((f) => ({ ...f, deploy_to_all: false }))}
                      />
                      <span className="text-sm text-ink">Specific servers</span>
                    </label>
                  </div>
                  {!form.deploy_to_all && (
                    pickable.length === 0 ? (
                      <p className="text-sm text-muted italic">
                        No servers are available for self-service. This key will be saved for owner review.
                      </p>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {pickable.map((s) => (
                          <button
                            key={s.id}
                            type="button"
                            onClick={() => toggleServer(s.id)}
                            className={`px-3 py-1 rounded text-sm font-mono border transition-colors ${
                              form.server_ids.includes(s.id)
                                ? "bg-accent/15 border-accent/50 text-accent"
                                : "bg-base border-line text-muted hover:border-faint"
                            }`}
                            title={s.allow_self_service ? "self-service" : "admin-only"}
                          >
                            {s.name}
                            {!s.allow_self_service && isAdmin && (
                              <span className="ml-1 text-faint">🔒</span>
                            )}
                          </button>
                        ))}
                      </div>
                    )
                  )}
                </div>
              );
            })()}
            {!isAdmin && servers.length === 0 && (
              <p className="text-sm text-muted">
                This key will be saved for the workspace owner to review. No servers are available for self-service deployment.
              </p>
            )}
            <div className="flex justify-end">
              <Button type="submit">Add key</Button>
            </div>
          </form>
        )}

        {loading ? (
          <ListSkeleton />
        ) : keys.length === 0 ? (
          <EmptyState
            icon={<KeyIcon className="w-9 h-9" />}
            title="No public keys found"
            hint="Add an SSH public key and it will be deployed to your servers automatically on the next sync."
            action={
              !showForm ? (
                <Button onClick={() => setShowForm(true)}>+ Add key</Button>
              ) : null
            }
          />
        ) : (
          <div className="space-y-3">
            {keys.map((k) => (
              <Card key={k.id} className="p-4">
                {editingId === k.id ? (
                  <div className="space-y-3">
                    <p className="text-sm font-mono text-muted">Editing: <span className="text-ink">{k.key_title}</span></p>
                    {servers.length > 0 && (
                      <div>
                        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mb-3">
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="radio"
                              checked={editForm.deploy_to_all}
                              onChange={() => setEditForm((f) => ({ ...f, deploy_to_all: true, server_ids: [] }))}
                            />
                            <span className="text-sm text-ink">All servers</span>
                          </label>
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="radio"
                              checked={!editForm.deploy_to_all}
                              onChange={() => setEditForm((f) => ({ ...f, deploy_to_all: false }))}
                            />
                            <span className="text-sm text-ink">Specific servers</span>
                          </label>
                        </div>
                        {!editForm.deploy_to_all && (
                          <div className="flex flex-wrap gap-2">
                            {servers.map((s) => (
                              <button
                                key={s.id}
                                type="button"
                                onClick={() => toggleServer(s.id, true)}
                                className={`px-3 py-1 rounded text-sm font-mono border transition-colors ${
                                  editForm.server_ids.includes(s.id)
                                    ? "bg-accent/15 border-accent/50 text-accent"
                                    : "bg-base border-line text-muted hover:border-faint"
                                }`}
                              >
                                {s.name}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                    <div className="flex gap-2">
                      <Button onClick={() => saveEdit(k.id)}>Save</Button>
                      <Button variant="secondary" onClick={cancelEdit}>Cancel</Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="font-mono font-medium text-ink">{k.key_title}</p>
                        <button
                          type="button"
                          onClick={() => handleToggle(k.id)}
                          title="Toggle whether this key is deployed"
                          className="inline-flex items-center p-0 border-0 bg-transparent leading-none cursor-pointer"
                        >
                          <Badge tone={k.is_active ? "accent" : "neutral"}>
                            {k.is_active ? "Active" : "Inactive"}
                          </Badge>
                        </button>
                        {isAdmin && !k.is_own && (
                          <Badge tone="violet">owner: {k.owner_username}</Badge>
                        )}
                      </div>
                      {k.fingerprint && (
                        <p className="text-xs text-muted font-mono mt-2 break-all" title="SSH SHA256 fingerprint — matches `ssh-keygen -lf`">
                          {k.fingerprint}
                        </p>
                      )}
                      <p className="text-xs text-faint font-mono mt-1 truncate">
                        {k.key_payload}
                      </p>
                      <p className="text-xs text-muted mt-2">
                        <span className="text-faint">deploys to: </span>{getServerNames(k)}
                      </p>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      {isAdmin && <Button variant="secondary" onClick={() => startEdit(k)}>Edit</Button>}
                      <Button variant="danger" onClick={() => handleDelete(k.id)}>Remove</Button>
                    </div>
                  </div>
                )}
              </Card>
            ))}
          </div>
        )}
      </div>
    </MainLayout>
  );
}
