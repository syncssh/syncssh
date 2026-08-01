// The axios interceptor lives outside the React tree, so it can't call
// useNavigate(). A component inside the router binds the navigate function
// here at mount; until then (or if it ever unbinds) we fall back to a hard
// location change so a 401 never gets stuck.
let _navigate = null;

export function bindNavigate(fn) {
  _navigate = fn;
}

export function goToLogin() {
  if (_navigate) _navigate("/login");
  else window.location.href = "/login";
}
