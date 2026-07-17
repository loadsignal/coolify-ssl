# Contributing

Thanks for helping improve coolify-ssl.

## Scope

This project targets **private LAN / VPN / Coolify homelab** TLS with mkcert — not public ACME / Let’s Encrypt.

## Development

```bash
# Unit + SSH-sync mocks + mkcert integration (needs mkcert + openssl on PATH)
sh tests/run.sh

# Image + Traefik proof (symlink leaf HTTPS + SAN renew)
docker build -t coolify-ssl:ci .
sh tests/traefik-smoke/run.sh
```

CI runs ShellCheck on `generate-certs.sh`, `lib/*.sh` (including `remote-publish.sh`), and tests, plus the test suite, amd64 + arm64 image builds, Traefik smoke, and Trivy on every PR.

Runtime logic lives in `lib/`; keep new helpers there rather than growing the entrypoint.

Please follow the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Pull requests

1. Keep changes focused; update `CHANGELOG.md` under `[Unreleased]` when behavior changes.
2. Do not commit CA keys, leaf keys, or real `ssh_known_hosts` material.
3. Prefer POSIX `sh` (no bashisms) in runtime scripts and tests.

## Security

Report vulnerabilities via [private GitHub security advisories](https://github.com/loadsignal/coolify-ssl/security/advisories/new) — see `SECURITY.md`.

Code of Conduct incidents: email `conduct@loadsignal.dev` (see `CODE_OF_CONDUCT.md`). Do not use security advisories for CoC reports.
