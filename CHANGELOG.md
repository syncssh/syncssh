# Changelog

All notable changes to SyncSSH are documented in this file. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-02

### Added

- Self-hosted Django control plane and React dashboard.
- Organization-scoped membership and role management.
- Server enrollment through one-shot install URLs.
- Cron-driven host worker with atomic managed-block updates.
- Global and server-targeted SSH public keys.
- Scoped API keys, audit logging, invitations, and outbound notifications.
- Docker Compose configurations for development and production.

### Security

- Hashed server and API tokens with one-time raw-token display.
- Bearer-header-only server synchronization.
- CSRF protection for browser mutations and rate limits for authentication,
  installation, and synchronization endpoints.
- Tenant-scoped queries, membership-aware key revocation, and organization
  deactivation controls.
- Validated public-key payloads and shell-safe installer generation.
- SSRF-resistant webhook delivery and validated reverse-proxy client IPs.
- Unprivileged production application containers.
