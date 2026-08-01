# Security Review

Review date: 2026-07-31

This document summarizes the security properties reviewed before the initial
public release. It is not a guarantee that the software is vulnerability-free.
Please report suspected vulnerabilities through the private process in
[SECURITY.md](SECURITY.md).

## Reviewed controls

- Server and API tokens are stored as hashes; raw values are returned only at
  creation or rotation.
- Server synchronization accepts bearer credentials only through the
  `Authorization` header. Query-string credentials are rejected.
- Install URLs are one-shot and generated shell values are validated and
  quoted.
- Public-key payloads reject newlines, managed-block markers, unknown key
  formats, NUL bytes, and oversized input.
- Server sync results are scoped by organization, active membership, key
  targeting, and server status.
- Session-authenticated mutations require CSRF protection.
- Organization deactivation blocks member/API access and causes enrolled
  servers to remove SyncSSH-managed keys on their next successful sync.
- Outbound webhook delivery validates public destinations, pins the approved
  address for the connection, and rejects redirects and URL credentials.
- Forwarded client addresses are trusted only from explicitly configured proxy
  networks. Cloudflare mode also validates the upstream proxy range.
- Production backend and notifier containers run as an unprivileged user.
- Production settings require a non-default secret and enable secure cookies,
  HTTPS redirect, HSTS, clickjacking protection, and content-type protections.

## Operational requirements

- Use HTTPS for every production deployment. Server and API credentials are
  bearer tokens and must not transit plaintext connections.
- Keep the origin inaccessible except through the configured reverse proxy.
- Keep `TRUSTED_PROXY_CIDRS` narrow. When using Cloudflare, populate
  `CLOUDFLARE_PROXY_CIDRS` from Cloudflare's current published ranges.
- Use Redis before running multiple Gunicorn workers so rate-limit state is
  shared across processes.
- Protect database, SMTP, and webhook credentials outside the repository and
  rotate any credential suspected of exposure.
- Apply dependency updates promptly and review CI security-scan failures before
  merging.

## Release verification

The CI workflow runs the backend test suite, frontend lint/build, and Gitleaks
for every pull request and update to `main`.

## Dependency audit note

As of this review, npm reports `GHSA-qwww-vcr4-c8h2` against React Router
7.18.2. The advisory concerns React Server Components and server actions;
SyncSSH is a client-rendered SPA and uses neither feature. React Router 7.11,
the alternative suggested by npm, reintroduces several browser and SSR
advisories fixed by 7.18.2. The project therefore remains on 7.18.2 and will
take the first upstream release that resolves the RSC advisory without those
regressions. Dependabot monitors both Python and npm dependencies weekly.
