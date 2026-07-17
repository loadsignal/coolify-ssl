# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- README is a short quick start; full reference moved to [docs/guide.md](./docs/guide.md)

## [0.1.0] - 2026-07-17

### Added

- Initial public release: mkcert CA bootstrap, Traefik leaf + dynamic provider, optional SSH leaf sync
- Modular POSIX layout under `lib/` (`common`, `validate`, `san`, `domains`, `ca`, `provider`, `leaf`, `sync`) with thin `generate-certs.sh` entrypoint
- Peer-side `lib/remote-publish.sh` (scp’d then executed) for reviewable remote atomic publish
- Conditional renewal: re-issue only when the leaf is missing, cert/key mismatch, SANs drifted, or expiry is within `RENEW_BEFORE_EXPIRY_SECONDS`
- Decoupled `CHECK_INTERVAL_SECONDS` (poll) and `RENEW_BEFORE_EXPIRY_SECONDS` (near-expiry); legacy `RENEW_INTERVAL_SECONDS` fills both when unset
- Canonical SAN comparison (IPv6 expanded, IPv4, DNS case-insensitive) so renew does not loop on textual form
- **Atomic leaf publish** (local + SSH peers): write `.gen.<id>/`, flip `.leaf` with `ln -sfn`, keep stable `CERT_NAME.cert`/`.key` symlinks; provider last (with `generated-at` stamp for file-watch reload)
- Flat-file migration into the `.leaf` layout on startup (upgrade-safe); hybrid symlink/flat leaf fails hard
- SSH sync skip when remote leaf cert DER SHA-256 already matches (requires `openssl` on the peer; fails open if missing)
- `CERT_SYNC_FAIL_BACKOFF_SECONDS` (default `60`) before STRICT fatal exit to avoid Docker restart storms
- Startup cleanup of orphaned stage / non-active `.gen.*` dirs; prune refuses to follow generation symlinks
- Strict validation for `CERT_NAME`, remote paths, domains, sync hosts, intervals, `MAX_DOMAINS`, and backoff
- Interruptible sleep in ≤60s chunks (`SIGTERM` / `SIGINT`)
- Persisted SSH `known_hosts` with `StrictHostKeyChecking=yes` (no TOFU / `accept-new`)
- Leaf sync each check cycle when `CERT_SYNC_HOSTS` is set (fingerprint skip when unchanged)
- Least-privilege SSH sync guide: [docs/ssh-least-privilege.md](./docs/ssh-least-privilege.md)
- Exclusive single-writer lock on `LOCK_FILE`; WARNING when sync user is `root`
- Default `TRUST_STORES=java` for `mkcert -install`
- Docker `HEALTHCHECK` + `STOPSIGNAL SIGTERM` + OCI labels
- Unit, SSH-sync (mocked ssh/scp + direct `remote-publish.sh`), mkcert integration, and **Traefik smoke** (`tests/traefik-smoke/`: HTTPS via symlink leaf + SAN renew)
- ShellCheck + Docker amd64/arm64 + Trivy (HIGH/CRITICAL) in CI; GHCR publish gated on CI; Cosign keyless; never `:latest`
- Dependabot, issue/PR templates, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
- Code of Conduct contact: `conduct@loadsignal.dev`

### Security

- Lab / self-hosted LAN only — not for internet-facing production TLS (see `SECURITY.md`)
- Container runs as root (Coolify mount ownership); documented in `SECURITY.md`
- Prefer binding one sync key under `/run/coolify-ssl/` and a dedicated peer user; root sync logs a WARNING
- Compose examples use `restart: on-failure:5` + sync fail backoff with `CERT_SYNC_STRICT=1`
- Single-writer lock fails fast if another coolify-ssl holds the cert volume
- Alpine **3.24** base image pinned by multi-arch digest; image sets `ENV TRUST_STORES=java`
- Full-directory Coolify SSH key mounts are rejected
- `CERT_SYNC_STRICT` defaults to `1` (abort on any SSH sync failure after backoff)
