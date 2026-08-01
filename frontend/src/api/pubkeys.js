import client from "./client";

export const getPublicKeys = () => client.get("/public-keys/");
export const createPublicKey = (data) => client.post("/public-keys/", data);
export const updatePublicKey = (id, data) => client.patch(`/public-keys/${id}/`, data);
export const deletePublicKey = (id) => client.delete(`/public-keys/${id}/`);
export const togglePublicKey = (id) => client.patch(`/public-keys/${id}/toggle/`);