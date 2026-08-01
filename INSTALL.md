# Installing syncssh

This guide walks you from zero to a working SSH-key-sync against a real
server in three scenarios:

- **[Quickstart — Docker Compose](#quickstart--docker-compose)** — bundled
  setup with a sandbox SSH target. Five minutes, no infra.
- **[Enrolling a real external server](#enrolling-a-real-external-server)** —
  control plane on your laptop, target VPS somewhere on the public internet.
- **[Production deployment](#production-deployment)** — self-hosted with
  TLS, real domain, Postgres + Redis.

For deeper troubleshooting and the full env-var matrix, jump to
[Pitfalls](#common-pitfalls) and [Troubleshooting](#troubleshooting) at
the bottom.

---

## The three URLs that matter

Every deployment confusion in syncssh traces back to one of these being
wrong for the scenario you're in. Keep this table mentally:

| Variable                | What it is                                                                          | Has to be reachable from               |
|-------------------------|-------------------------------------------------------------------------------------|----------------------------------------|
| `APP_BASE_URL`          | Backend URL in browser-facing redirects (invite accept, email confirm).             | Users' browsers.                       |
| `VITE_INSTALL_BASE_URL` | Backend URL the dashboard renders into the curl install command — the command *runs on the target server*. | Every server you enroll. |
| `CORS_ORIGINS`          | Comma-separated list of frontend origins the backend accepts cookies from.          | Frontend → backend, browser-side.      |

**Rule of thumb**: on a real deployment (tunnel or public host) all of
these carry the same public URL. They only diverge in local docker dev,
where browsers need `localhost:8000` but the bundled testvps sandbox
needs the docker-DNS name `backend:8000`.

---

## How it works

```
┌──────────────────┐
│  Admin browser   │  the dashboard
└────────┬─────────┘
         │ XHR — origin must be in CORS_ORIGINS
         ▼
┌──────────────────┐
│  syncssh backend │  knows itself as APP_BASE_URL
│  (control plane) │  generates install scripts that bake APP_BASE_URL in
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Target server   │  cron pulls authorized_keys from APP_BASE_URL every minute
│  (cron + curl)   │  — APP_BASE_URL must resolve from here, or nothing syncs
└──────────────────┘
```

---

## Quickstart — Docker Compose

Use this to evaluate the product end-to-end without renting a VPS. The
bundled `testvps` service is an SSH sandbox on the same docker network as
the backend.

**Requirements:** Docker + Docker Compose v2.

```bash
git clone https://github.com/syncssh/syncssh.git
cd syncssh
cp .env.example .env
# edit .env: replace SECRET_KEY with anything non-empty for dev
docker compose up -d
```

**Try it:**

1. Browser → http://localhost:5173. Sign up. (The "Solo developer" vs
   "Team" choice is informational only — both create the same workspace
   with you as owner, and either can invite members later. The answer is
   recorded on the `auth.signup` audit event and changes nothing else.)
2. Add a server in the dashboard. Copy the install command shown — it
   will look like `curl -sL http://backend:8000/api/v1/install/<token>/ | bash`.
3. SSH into the bundled sandbox:
   ```bash
   ssh root@localhost -p 2222
   # password: whatever you set as VPS_ROOT_PASSWORD (default "syncssh")
   ```
4. **Inside the testvps container**, paste the install command as-is
   (docker's internal DNS resolves `backend` to the backend container).
5. Back in the dashboard, add your SSH public key. Wait ~60 seconds.
6. On the sandbox: `cat ~/.ssh/authorized_keys` — your key now appears
   inside the `# === SYNCSSH BEGIN ===` block.

**Why `backend:8000` and not `localhost:8000`**: the install command runs
*on the target server*, where `localhost` would loop back to the target
itself, not the control plane. Two env vars keep the URLs straight:
`VITE_INSTALL_BASE_URL` controls the host baked into the copyable install
command, and `SYNC_BASE_URL` controls the URL the agent's recurring cron
sync hits. Both default to `http://backend:8000` for the bundled testvps
sandbox, while `APP_BASE_URL` stays `localhost` for browser-facing
invite/confirm links. When enrolling a real external server (next
section), point `VITE_INSTALL_BASE_URL` and `SYNC_BASE_URL` at your
tunnel/public URL instead.

---

## Enrolling a real external server

You want to enroll an actual VPS (AWS EC2, Hetzner, a homelab box) while
the control plane runs on your laptop.

**The problem**: the VPS can't resolve `backend` or reach your laptop's
`localhost`. The install script's curl dies at DNS.

**The fix**: punch a hole. A free tunnel is the easiest option.

### Cloudflared tunnel (recommended)

```bash
# install once
brew install cloudflared          # macOS
# or: https://github.com/cloudflare/cloudflared/releases

# in a separate terminal, while docker compose is up:
cloudflared tunnel --url http://localhost:8000
```

Cloudflared prints a hostname like `https://random-words-1234.trycloudflare.com`.

Edit `.env`:

```env
APP_BASE_URL=https://random-words-1234.trycloudflare.com
VITE_INSTALL_BASE_URL=https://random-words-1234.trycloudflare.com
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0,backend,random-words-1234.trycloudflare.com
```

Reload the backend:

```bash
docker compose restart backend
```

Now the install URL shown in the dashboard points at the tunnel; the VPS
can curl it; the cron worker on the VPS can keep pulling sync data over
the tunnel forever. (Or until cloudflared restarts and gets a new
hostname — fine for debugging, not for anything persistent.)

### Alternative: ngrok, port-forward, Tailscale

Same shape, different vendor:

- **ngrok**: `ngrok http 8000` → use the printed `https://*.ngrok-free.app`.
- **Port-forward**: if you have a static IP, forward `:8000` to a
  DuckDNS / no-ip hostname.
- **Tailscale**: put your laptop and the VPS on the same tailnet, use
  `APP_BASE_URL=http://your-laptop.tail-scale-name:8000`. Best option for
  ongoing dev against persistent VPSes — no public exposure.

**Don't forget `ALLOWED_HOSTS`**: Django will reject any request whose
`Host:` header isn't listed. The tunnel hostname must be added or you'll
get bare 400 responses with no helpful error.

---

## Production deployment

The steady state: one server hosts everything behind a real domain with a
real certificate.

```
internet
   │
   ▼
┌──────────────┐
│  reverse     │  nginx / Caddy / Traefik
│  proxy       │  terminates TLS on :443
└──────┬───────┘
       │ proxies to backend:8000 (internal)
       ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  backend     │──│  Postgres    │  │  Redis       │
│  (gunicorn)  │  │              │  │ (rate limit) │
└──────────────┘  └──────────────┘  └──────────────┘
```

### `.env`

```env
DEBUG=False
SECRET_KEY=...                              # openssl rand -base64 64
ALLOWED_HOSTS=ssh.yourco.com

APP_BASE_URL=https://ssh.yourco.com
VITE_INSTALL_BASE_URL=https://ssh.yourco.com
CORS_ORIGINS=https://ssh.yourco.com
TRUSTED_PROXY=xff
TRUSTED_PROXY_CIDRS=172.16.0.0/12

DB_HOST=postgres.internal
DB_NAME=syncssh
DB_USER=syncssh
DB_PASSWORD=...

# real SMTP for invite delivery
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.sendgrid.net
EMAIL_HOST_USER=apikey
EMAIL_HOST_PASSWORD=...
EMAIL_PORT=587
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=noreply@yourco.com
```

### Reverse proxy

Caddy gives you the simplest TLS story:

```caddy
ssh.yourco.com {
    handle /assets/* {
        root * /var/www/syncssh/frontend/dist
        file_server
    }
    handle /api/*     { reverse_proxy 127.0.0.1:8000 }
    handle /install/* { reverse_proxy 127.0.0.1:8000 }
    handle /accounts/* { reverse_proxy 127.0.0.1:8000 }
    handle {
        root * /var/www/syncssh/frontend/dist
        try_files {path} /index.html
        file_server
    }
}
```

For nginx, set `proxy_set_header X-Forwarded-Proto $scheme;` explicitly —
syncssh trusts that header to recognize HTTPS-terminated requests.

### Production checklist

- [ ] `DEBUG=False` — the app refuses to boot without a strong `SECRET_KEY`.
- [ ] Postgres (not SQLite).
- [ ] Redis-backed cache for rate limits (the default in-memory cache is
      per-worker and per-process, so per-IP throttles weaken on every
      restart or scale-out).
- [ ] HTTPS via reverse proxy. Plain HTTP exposes bearer tokens.
- [ ] `APP_BASE_URL` matches the public URL exactly (no trailing slash).
- [ ] Database backups configured.

When `DEBUG=False`, syncssh automatically enforces `SESSION_COOKIE_SECURE`,
`CSRF_COOKIE_SECURE`, `SECURE_SSL_REDIRECT`, HSTS with subdomains and
preload, `X_FRAME_OPTIONS=DENY`, `SECURE_REFERRER_POLICY=same-origin`,
and `SECURE_CONTENT_TYPE_NOSNIFF`. You don't have to configure any of
these — they're locked on whenever debug mode is off.

---

## Common pitfalls

**1. The agent's sync URL doesn't resolve from the target server.**
Symptom: install completes, but `cat ~/.ssh/authorized_keys` never shows
keys. Cron is silently failing on DNS.
Fix: the install script bakes in `SYNC_BASE_URL` (falling back to
`APP_BASE_URL`), and that URL must resolve from the target server. For a
docker-network target, set `SYNC_BASE_URL=http://backend:8000` while
keeping `APP_BASE_URL=http://localhost:8000` for browser-facing links.

**2. `ALLOWED_HOSTS` doesn't include the new tunnel/domain.**
Symptom: bare 400 with "Bad Request" and nothing useful in the body.
Fix: add the hostname (no scheme, no port).

**3. `APP_BASE_URL` and `VITE_INSTALL_BASE_URL` diverged.**
Symptom: dashboard shows curl pointed at host A; install completes; but
the agent's `/servers/sync` calls hit host B and 404 forever.
Fix: keep them identical.

**4. Rate-limit cache resets every gunicorn restart.**
Symptom: per-IP and per-username throttles "leak" after a deploy.
Fix: configure a Redis-backed cache. The default is per-worker and
per-process.

**5. Install URL replay returns 410.**
Symptom: re-running the install command after a successful install
prints `syncssh-install: Install URL already used. …` and exits 1.
Not a bug — install URLs are one-shot. Rotate the server token from the
dashboard to re-arm.

**6. The dashboard works on localhost but `:5173` is unreachable from
another LAN device.**
Vite's dev server binds to `127.0.0.1` by default. Pass `--host 0.0.0.0`
to the frontend service to bind on all interfaces.

---

## Troubleshooting

### Agent installed but nothing syncs

```bash
# on the target server, check the cron
crontab -l                       # should show "* * * * * $HOME/.syncssh/sync-ssh.sh"

# run the worker manually with verbose curl
bash -x ~/.syncssh/sync-ssh.sh
```

Interpret the curl result:

| Response | Meaning | Fix |
|----------|---------|-----|
| curl fails (DNS / connection) | `APP_BASE_URL` not reachable from this host. | Use a tunnel (scenario B) or a real public URL (scenario C). |
| `401` | The server's sync token is stale (someone rotated it server-side). | Rotate the server in the dashboard and re-run the install. |
| `410` | Install URL was replayed. | Rotate the server token, get a new install URL, re-run. |
| `200` with no key text | No keys assigned to this server yet, **or** the user who owns the keys is no longer a member of the org. | Add keys / restore membership. |

### Backend logs show nothing useful

```bash
docker compose logs -f backend
```

Bare "Bad Request (400)" with no detail almost always means
`ALLOWED_HOSTS`. Briefly set `DEBUG=True` to see Django's verbose error
for the offending Host header, fix `ALLOWED_HOSTS`, set `DEBUG=False`
again.

### Frontend shows "Network Error" on every API call

```bash
curl -i http://localhost:5173/api/v1/auth/csrf/
```

- `200` → proxy is fine; check `CORS_ORIGINS` covers your dashboard origin.
- `502` → backend is down; `docker compose ps` and `logs backend`.
- `404` → `VITE_API_PROXY` points at the wrong target.

---

## Env var reference

| Var                      | Used by         | Required                         | Default                              | Notes                                                                                          |
|--------------------------|-----------------|----------------------------------|--------------------------------------|------------------------------------------------------------------------------------------------|
| `SECRET_KEY`             | backend         | yes (when `DEBUG=False`)         | dev fallback                         | Sessions + CSRF + password reset signing. Rotate = log everyone out.                           |
| `DEBUG`                  | backend         | no                               | `False`                              | `True` for local dev. Enforces production security toggles automatically when `False`.         |
| `SYNCSSH_EDITION`        | backend         | no                               | `cloud`                              | `oss` \| `cloud`. Selects the open-core feature set. `oss` disables webhooks and invite-email theming, and caps audit-log history at 30 days. The enabled features are reported to the frontend (`/auth/me/`), so one backend var drives both. |
| `ALLOWED_HOSTS`          | backend         | yes                              | `localhost,127.0.0.1`                | Comma-separated. Must include every `Host:` header the backend should accept.                  |
| `DB_HOST/PORT/NAME/USER/PASSWORD` | backend | yes                              | dev compose defaults                 | Postgres in production.                                                                        |
| `APP_BASE_URL`           | backend         | yes                              | `http://localhost:8000`              | Browser-facing redirects (invite accept, email confirm). Must be browser-resolvable.           |
| `SYNC_BASE_URL`          | backend         | no                               | inherits `APP_BASE_URL`              | URL baked into the install script for the agent's sync cron. Must resolve from the *target server* — set to `http://backend:8000` only when targets reach the backend over docker DNS (e.g. testvps). |
| `CORS_ORIGINS`           | backend         | yes                              | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated. Doubles as `CSRF_TRUSTED_ORIGINS`.                            |
| `TRUSTED_PROXY`          | backend         | production                       | unset                                | `xff` for the bundled Caddy stack or `cloudflare` behind Cloudflare. Forwarded headers remain ignored unless the proxy CIDRs below are configured. |
| `TRUSTED_PROXY_CIDRS`    | backend         | with `TRUSTED_PROXY`             | compose: `172.16.0.0/12`             | Comma-separated networks allowed to supply forwarded client-address headers. Narrow this when using a fixed container network. |
| `CLOUDFLARE_PROXY_CIDRS` | backend         | Cloudflare mode                  | unset                                | Current Cloudflare IPv4/IPv6 proxy ranges. A missing or nonmatching range causes `CF-Connecting-IP` to be ignored. |
| `EMAIL_BACKEND`          | backend         | no                               | console                              | Switch to SMTP for prod.                                                                       |
| `DEFAULT_FROM_EMAIL`     | backend         | no                               | `noreply@syncssh.dev`                | Visible to invite recipients.                                                                  |
| `VITE_API_PROXY`         | frontend (dev)  | dev only                         | `http://backend:8000`                | Where Vite's dev server proxies `/api` calls. Build-time, not runtime.                         |
| `VITE_INSTALL_BASE_URL`  | frontend        | yes                              | `http://backend:8000`                | Backend URL the dashboard renders into the curl install command. Must resolve from the *target server* — the default fits the bundled testvps; use your public URL for external servers.        |
| `VPS_ROOT_PASSWORD`      | compose testvps | dev only                         | `syncssh`                            | Sandbox-only. Never set in any env that touches production.                                    |

---

## Found something missing?

Open an issue. The deployment matrix is documented from real deployments
we've done, but if you hit a scenario this guide doesn't cover — say so —
that's the highest-value PR a new contributor can make.
