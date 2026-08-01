# Architecture

SyncSSH is a self-hosted control plane for distributing SSH public keys. Hosts
pull their desired `authorized_keys` state; the control plane never needs
inbound SSH access to managed servers.

## Components

- **Django API** — authentication, organizations, roles, servers, public keys,
  audit events, invitations, and outbound notifications.
- **React dashboard** — browser UI served by Vite in development and Caddy in
  production.
- **Host worker** — a generated shell script installed per server and invoked
  by cron. It fetches server-scoped keys with a bearer token and replaces only
  the SyncSSH-managed block in `authorized_keys`.
- **PostgreSQL** — durable application state. Raw server and API tokens are not
  stored; only hashes and display prefixes are persisted.
- **Caddy** — TLS termination and routing for the production Docker stack.

## Request flow

1. An administrator registers a server and receives a one-shot install URL.
2. The installer writes the worker and its bearer token to the target account.
3. The worker periodically requests `/api/v1/servers/sync` using the
   `Authorization` header.
4. The API resolves the token hash, organization, active membership, and key
   targeting rules, then returns newline-separated OpenSSH public keys.
5. The worker atomically replaces the managed block while preserving keys
   outside it. Failed or invalid responses leave the existing file untouched.

## Trust boundaries

- Browser mutations use session authentication plus CSRF protection.
- Machine API keys and server sync tokens use bearer authentication.
- Organization filters are applied before object lookup to preserve tenant
  isolation.
- Forwarded client-IP headers are accepted only from explicitly configured
  proxy networks.
- Production traffic must use HTTPS because bearer credentials transit the
  control-plane boundary.

Deployment details and environment variables are documented in
[INSTALL.md](INSTALL.md).
