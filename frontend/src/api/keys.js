import client from "./client";

export const getKeys = () => client.get("/org/keys/");
export const createKey = (data) => client.post("/org/keys/", data);
export const deleteKey = (id) => client.delete(`/org/keys/${id}/`);
export const rotateKey = (id) => client.post(`/org/keys/${id}/rotate/`);