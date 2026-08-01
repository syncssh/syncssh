import client from "./client";

export const getOrg = () => client.get("/org/");
export const leaveWorkspace = () => client.post("/org/leave/");
export const getMemberships = () => client.get("/org/memberships/");
export const leaveMembership = (organizationId) => client.post(`/org/memberships/${organizationId}/leave/`);
export const removeMember = (userId) => client.delete(`/org/members/${userId}/`);
export const updateOrg = (data) => client.patch("/org/", data);
export const getWebhook = () => client.get("/org/webhook/");
export const saveWebhook = (data) => client.put("/org/webhook/", data);
export const patchWebhook = (data) => client.patch("/org/webhook/", data);
export const rotateWebhookSecret = () => client.post("/org/webhook/rotate/");
export const sendTestWebhook = () => client.post("/org/webhook/test/");
export const deleteWebhook = () => client.delete("/org/webhook/");
export const getServers = () => client.get("/org/servers/");
export const createServer = (data) => client.post("/org/servers/", data);
export const deleteServer = (id) => client.delete(`/org/servers/${id}/`);
export const rotateServerToken = (id) => client.post(`/org/servers/${id}/rotate/`);
export const updateServer = (id, data) => client.patch(`/org/servers/${id}/`, data);
