<!-- markdownlint-disable first-line-h1 no-inline-html -->
<p align="center">
  <img width="112" src="frontend/public/favicon.svg" alt="syncssh logo" />
</p>

<h1 align="center">syncssh</h1>

<p align="center">
  <strong>Centralized SSH key management for your server fleet.</strong><br />
  Add a key once, deploy it everywhere. Remove it, and it vanishes from every host in seconds.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License: AGPL-3.0" /></a>
  <a href="https://github.com/syncssh/syncssh/actions/workflows/ci.yml"><img src="https://github.com/syncssh/syncssh/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
</p>

---

No SSH gateway, no inline proxy, no bastion to keep alive — just a tiny cron on
each host that pulls its `authorized_keys` from a control plane you run. Your
servers keep accepting plain `ssh user@host`; the only thing that changes is
*who controls the keys*.

## Quickstart

```bash
git clone https://github.com/syncssh/syncssh.git
cd syncssh
cp .env.example .env        # change SECRET_KEY; dev defaults are fine for the rest
docker compose up --build
```

Then open <http://localhost:5173>, create an org, and add a server — you'll get
a one-shot install command. Paste it on any host:

```bash
curl -fsSL https://your-control-plane/api/v1/install/<token>/ | bash
```

Add your public key in the dashboard and it lands in the host's
`~/.ssh/authorized_keys` within ~60s. Remove it, and it's gone just as fast.

> The bundled `testvps` (`ssh root@localhost -p 2222`, password `syncssh`) is a
> sandbox target so you can watch the whole loop end to end.

Enrolling a real external VPS, or going to production with TLS? See
[INSTALL.md](INSTALL.md) — it covers the env-var matrix, tunneling options,
reverse-proxy config, and troubleshooting.

## How it works

```
  Admin/Dev UI  ──►  syncssh control plane  ◄──  each host (cron pull)
   (web app)          (Django + Postgres)         rewrites authorized_keys
```

Three parts: the **control plane** (this repo), a **~30-line bash agent** run by
cron, and a **256-bit bearer token** per server (stored only as a SHA-256 hash,
shown once). Hosts always initiate the pull, so it works behind NAT with no
inbound ports and no daemon to crash.

<details>
<summary><strong>Security properties</strong></summary>

- Bearer tokens (sync tokens, API keys) stored as SHA-256 hashes — raw value shown once, never persisted.
- Install URLs are one-shot; replays return 410. Rotate the server token to re-arm.
- Two-tier rate limits on sync (per-token + per-IP); per-username login throttle on top of per-IP.
- CSRF enforced on every session-authenticated mutation.
- Sync responses are server-scoped — a host only ever sees the keys destined for it.
- Org-scoped everything; no cross-tenant lookups are possible.

Found a security issue? Use GitHub's **Security → Report a vulnerability**
button on this repo — that opens a private advisory only the maintainer can
see. Please don't file public issues for security bugs.
</details>

<details>
<summary><strong>Production deployment</strong></summary>

See **[INSTALL.md](INSTALL.md)** for the full deployment guide — covers
the docker-compose quickstart, enrolling external VPSes via a tunnel,
production self-hosting with TLS, the env-var reference, common pitfalls,
and troubleshooting.

The short version:

- Set `DEBUG=False` and a real `SECRET_KEY`.
- Set `APP_BASE_URL` to your public HTTPS URL (embedded in install commands + invite links).
- Terminate TLS at a reverse proxy (nginx/Caddy) — bearer tokens go over the wire, HTTPS is mandatory.
- Use Postgres, not SQLite.
- Configure SMTP for invite emails.
- Swap the rate-limit cache to Redis (the default in-memory cache isn't shared across Gunicorn workers).
</details>

## License

[AGPL-3.0](LICENSE). You can run, modify, and use syncssh commercially. If you
modify it **and offer it as a network service**, you must publish your changes
under the same license. Need different terms for a proprietary product? A
commercial license is available — reach out.

## Contributing

Issues and discussions are welcome. Please open a proposal before starting a
large change so implementation and product direction can be agreed first.
