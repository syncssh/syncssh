import client from "./client";

export const getCsrf = () => client.get("/auth/csrf/");

// Guard against the race where a user lands directly on /login or /signup
// and submits before AuthProvider's startup getCsrf() resolves. Without the
// cookie set, Django's CSRF middleware would 403 the POST.
const ensureCsrf = async () => {
  if (!document.cookie.match(/csrftoken=/)) await getCsrf();
};

export const login = async (username, password) => {
  await ensureCsrf();
  return client.post("/auth/login/", { username, password });
};

export const logout = () => client.post("/auth/logout/");

export const signup = async (data) => {
  await ensureCsrf();
  return client.post("/auth/signup/", data);
};

export const getMe = () => client.get("/auth/me/");

export const updateMe = (data) => client.patch("/auth/me/", data);

export const changePassword = (data) => client.post("/auth/change-password/", data);