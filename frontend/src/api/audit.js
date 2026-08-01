import client from "./client";

export const getAuditLog = (params = {}) =>
  client.get("/audit/", { params });
