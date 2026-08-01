# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through
[Security → Report a vulnerability](https://github.com/syncssh/syncssh/security/advisories/new).
You'll get an acknowledgement within a few days.

Include what you can:

- A description of the issue and its impact.
- Steps to reproduce (a minimal setup with the bundled `testvps` sandbox is ideal).
- The commit or release you tested against.

## Scope

Anything in this repository is in scope — the Django control plane, the React
dashboard, the generated shell worker, and the Docker/deployment configuration.
Particularly interesting areas: the install-token flow (`/install/<token>/`),
the authenticated sync endpoint, `authorized_keys` handling on target hosts,
and organization/role boundaries.

Out of scope: denial of service against your own self-hosted instance,
issues requiring a compromised control-plane host, and reports from automated
scanners without a demonstrated impact.

## Supported versions

SyncSSH is pre-1.0. Only the latest release (and `main`) receive security
fixes — there are no backports.

## Disclosure

We ask for coordinated disclosure: give us a reasonable window to ship a fix
before publishing details. Fixed vulnerabilities are credited in the changelog
unless you prefer otherwise.
