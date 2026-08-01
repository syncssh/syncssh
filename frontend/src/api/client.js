import axios from "axios";
import { goToLogin } from "./navigation";

const API_BASE = "/api/v1";

const client = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

client.interceptors.request.use((config) => {
  const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[0]?.split("=")[1];
  if (csrf && ["post", "put", "patch", "delete"].includes(config.method?.toLowerCase())) {
    config.headers["X-CSRFToken"] = csrf;
  }
  return config;
});

client.interceptors.response.use(
  (res) => res,
  (err) => {
    const publicPaths = ["/login", "/signup"];
    const isPublic = publicPaths.some((p) => window.location.pathname.startsWith(p));
    if (err.response?.status === 401 && !isPublic) {
      // Drop the now-stale session so ProtectedRoute can't flash protected
      // content, then redirect in-app (no full page reload) when possible.
      window.dispatchEvent(new Event("auth:unauthorized"));
      goToLogin();
    }
    return Promise.reject(err);
  }
);

export default client;