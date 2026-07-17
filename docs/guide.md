# coolify-ssl guide

Full reference for deploying and operating coolify-ssl. For a short path to a working setup, see the [README](../README.md).

**Private LAN / VPN  only** — not a public CA and not a replacement for Let’s Encrypt. Read [SECURITY.md](../SECURITY.md) before enabling SSH sync or distributing `rootCA.pem`.

Image: [`ghcr.io/loadsignal/coolify-ssl`](https://ghcr.io/loadsignal/coolify-ssl) — pin a version tag (e.g. `0.1.0`), not `:latest`. Published images include provenance/SBOM attestations and are signed with keyless Cosign (verify with `cosign verify`).

## What it does

1. Bootstraps (or reuses) a mkcert CA on a volume
2. Issues a leaf cert (`lan.cert` / `lan.key` by default) for your SANs
3. Writes Traefik’s dynamic file provider so the proxy reloads
4. Optionally copies the **leaf only** (never the CA) to peer Coolify hosts over SSH
5. Re-checks on an interval and re-issues only when needed (SAN drift / near expiry / missing leaf)
6. When `CERT_SYNC_HOSTS` is set, syncs each check cycle unless the remote leaf fingerprint already matches

CI proves Traefik can terminate TLS through the atomic `.leaf` symlink layout **and after a SAN-driven renew** (`tests/traefik-smoke/`).

## Deploy (Coolify)

1. Create a **Docker Compose** resource on the proxy server
2. Paste [`docker-compose.example.yml`](../docker-compose.example.yml)
3. Set domains (`SSL_DOMAINS` or File Mount at `/etc/ssl-gen/domains.txt`)
4. For leaf sync: set `CERT_SYNC_HOSTS`, seed `known_hosts`, uncomment the **single-key** volume, set `CERT_SYNC_SSH_KEY_PATH`

```yaml
services:
  coolify-ssl:
    image: ghcr.io/loadsignal/coolify-ssl:0.1.0
    restart: on-failure:5
    stop_grace_period: 30s
    environment:
      CERT_NAME: ${CERT_NAME:-lan}
      CHECK_INTERVAL_SECONDS: ${CHECK_INTERVAL_SECONDS:-2592000}
      RENEW_BEFORE_EXPIRY_SECONDS: ${RENEW_BEFORE_EXPIRY_SECONDS:-2592000}
      SSL_DOMAINS: ${SSL_DOMAINS:-}
      CERT_SYNC_HOSTS: ${CERT_SYNC_HOSTS:-}
      CERT_SYNC_SSH_USER: ${CERT_SYNC_SSH_USER:-root}
      CERT_SYNC_SSH_PORT: ${CERT_SYNC_SSH_PORT:-22}
      CERT_SYNC_SSH_KEY_PATH: ${CERT_SYNC_SSH_KEY_PATH:-/run/coolify-ssl/sync.key}
      CERT_SYNC_STRICT: ${CERT_SYNC_STRICT:-1}
      CERT_SYNC_FAIL_BACKOFF_SECONDS: ${CERT_SYNC_FAIL_BACKOFF_SECONDS:-60}
      REMOTE_CERT_DIR: ${REMOTE_CERT_DIR:-/data/coolify/proxy/certs}
      REMOTE_DYNAMIC_DIR: ${REMOTE_DYNAMIC_DIR:-/data/coolify/proxy/dynamic}
      SSH_KNOWN_HOSTS_FILE: ${SSH_KNOWN_HOSTS_FILE:-/caroot/ssh_known_hosts}
    volumes:
      - /data/coolify/ca:/caroot
      - /data/coolify/proxy/certs:/certs
      - /data/coolify/proxy/dynamic:/dynamic
      # Optional leaf sync — ONE key file only (replace <uuid>):
      # - /data/coolify/ssh/keys/ssh_key@<uuid>:/run/coolify-ssl/sync.key:ro
```

Build from this repo instead: [`docker-compose.coolify.yml`](../docker-compose.coolify.yml) (Base Directory `/`).

## Domains

**Env** (Coolify → Environment Variables):

```env
SSL_DOMAINS=app.example.lan,grafana.example.lan,*.tools.example.lan,10.0.0.4
```

**File Mount** → `/etc/ssl-gen/domains.txt` (wins when non-empty). Format: see [`domains.example.txt`](../domains.example.txt).

Accepted SANs: DNS hostnames, `*.a.b` wildcards, IPv4, IPv6. Shell metacharacters and invalid labels/octets are rejected.  
`*.lan` is rejected (wildcard directly under a TLD). X.509 wildcards only cover one label (`*.tools.lan` does not match `a.b.tools.lan`).

`CERT_SYNC_HOSTS` accepts hostname or IPv4 only (OpenSSH IPv6 literals need brackets; not supported here).

**After changing SANs:** restart the service (default check interval is 30 days).

## Volumes

| Host path | Container | Role |
|-----------|-----------|------|
| `/data/coolify/ca` | `/caroot` | Persistent CA + default `ssh_known_hosts` |
| `/data/coolify/proxy/certs` | `/certs` | Leaf: `lan.cert` / `lan.key` (symlinks into `.leaf/`) |
| `/data/coolify/proxy/dynamic` | `/dynamic` | Traefik file provider (`local-certs.yaml`) |
| `/data/coolify/ssh/keys/ssh_key@<uuid>` | `/run/coolify-ssl/sync.key` | **Optional** — one Coolify SSH key for leaf sync (ro) |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_NAME` | `lan` | Leaf basename (`A-Za-z0-9._-`) |
| `CHECK_INTERVAL_SECONDS` | `2592000` | Poll interval (`60`–`315360000`) |
| `RENEW_BEFORE_EXPIRY_SECONDS` | `2592000` | Re-issue when expiry is within this window |
| `RENEW_INTERVAL_SECONDS` | — | **Legacy:** fills both check + near-expiry when unset |
| `MAX_DOMAINS` | `64` | Maximum SAN count |
| `SSL_DOMAINS` | — | SANs (ignored if File Mount is non-empty) |
| `CERT_SYNC_HOSTS` | — | SSH sync targets (empty = local only) |
| `CERT_SYNC_SSH_USER` | `root` | Remote SSH user (prefer dedicated — see least-privilege doc) |
| `CERT_SYNC_SSH_PORT` | `22` | SSH port |
| `CERT_SYNC_SSH_KEY_PATH` | `/run/coolify-ssl/sync.key` | Bind-mounted sync key path |
| `CERT_SYNC_STRICT` | `1` | `1` = abort if any sync fails |
| `CERT_SYNC_FAIL_BACKOFF_SECONDS` | `60` | Sleep before STRICT exit (restart-storm guard; `0` disables) |
| `REMOTE_CERT_DIR` | `/data/coolify/proxy/certs` | Certs dir on remotes |
| `REMOTE_DYNAMIC_DIR` | `/data/coolify/proxy/dynamic` | Traefik dynamic dir on remotes |
| `SSH_KNOWN_HOSTS_FILE` | `/caroot/ssh_known_hosts` | Persisted known_hosts |
| `LOCK_FILE` | `$CERT_DIR/.coolify-ssl.lock` | Exclusive writer lock |
| `TRUST_STORES` | `java` | mkcert `-install` targets |

See [`.env.example`](../.env.example).

## Limits (read once)

- Private trust: clients must install your `rootCA.pem`
- Re-issue is conditional (missing / key mismatch / SAN drift / near expiry) — not a blind re-mint
- SAN comparison canonicalizes IPv6, IPv4, and DNS case
- At most `MAX_DOMAINS` SANs (default `64`)
- SSH sync needs a seeded `known_hosts` (`StrictHostKeyChecking=yes`); fingerprint skip needs `openssl` on the peer (otherwise sync always runs)
- Default sync user is `root` — treat that key as high privilege; WARNING logged
- Container runs as root (Coolify mount ownership)
- Mount **one** SSH key under `/run/coolify-ssl/` — never the whole Coolify keys directory
- Local + remote leaf publish is atomic via `.leaf` generation flip; peer side runs `lib/remote-publish.sh`
- One writer per cert volume (`flock` / mkdir lock)
- `restart: on-failure` + `CERT_SYNC_FAIL_BACKOFF_SECONDS` recommended with `CERT_SYNC_STRICT=1`

## SSH leaf sync

```bash
ssh-keyscan -H 10.0.0.5 >> /data/coolify/ca/ssh_known_hosts
```

```env
CERT_SYNC_HOSTS=10.0.0.5
CERT_SYNC_SSH_KEY_PATH=/run/coolify-ssl/sync.key
CERT_SYNC_STRICT=1
```

Uncomment the single-key volume in compose. Prefer a dedicated sync user — [ssh-least-privilege.md](./ssh-least-privilege.md).

## Trusting the CA

On the host under `/data/coolify/ca`:

- `rootCA.pem` — install on clients
- `rootCA-key.pem` — **never** distribute
- `ssh_known_hosts` — peer host keys for leaf sync

```bash
# macOS (Safari / Chrome use the system keychain)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rootCA.pem

# Linux (Debian/Ubuntu)
sudo cp rootCA.pem /usr/local/share/ca-certificates/coolify-ssl.crt
sudo update-ca-certificates
```

**Firefox** uses its own certificate store (not the macOS/Linux system store). Import `rootCA.pem` in Firefox → Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import…, and trust it for websites.

## How it works

```text
startup → validate → exclusive lock → cleanup orphans → migrate flat leaf
       → CA bootstrap → SSH setup (if sync) → read domains
loop:
  if needs renewal → write .gen.<id>/ → flip .leaf → write provider (stamped)
  if CERT_SYNC_HOSTS → fingerprint skip or scp leaf+provider+remote-publish.sh → run script
  sleep CHECK_INTERVAL_SECONDS (≤60s chunks) → re-read domains
```

Implementation: `lib/` (`common`, `validate`, `san`, `domains`, `ca`, `provider`, `leaf`, `sync`) + `lib/remote-publish.sh` on peers. Entrypoint: `generate-certs.sh`.

## Local build & test

```bash
docker build -t coolify-ssl:ci .
sh tests/run.sh                    # mkcert + openssl on PATH
sh tests/traefik-smoke/run.sh      # Traefik HTTPS via symlink leaf + renew
```

See [CONTRIBUTING.md](../CONTRIBUTING.md). Security: [SECURITY.md](../SECURITY.md). CoC: `conduct@loadsignal.dev`.

CI: ShellCheck, unit/SSH-sync/integration tests, Docker amd64+arm64, **Traefik smoke**, Trivy (HIGH/CRITICAL). Publish to GHCR is gated on CI; never tags `:latest`.

### Verify a published image

```bash
cosign verify \
  --certificate-identity-regexp 'https://github.com/loadsignal/coolify-ssl/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/loadsignal/coolify-ssl:0.1.0
```

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Container exits immediately | Logs: missing domains, invalid env, inconsistent CA / hybrid leaf |
| `SSH known_hosts empty or missing` | Seed peers: `ssh-keyscan -H <peer> >> /data/coolify/ca/ssh_known_hosts`, then restart |
| Browsers still warn | Client has not trusted `rootCA.pem`; wrong leaf SANs; Firefox needs its own import |
| Traefik ignores cert | Provider path / `CERT_NAME`; volume mounts; file watch enabled? |
| SSH sync fails | `known_hosts`? Single-key volume? Peer has `openssl` for skip? (`CERT_SYNC_STRICT=1` aborts after backoff) |
| Restart loop on sync failure | Fix peer/key/`known_hosts`; backoff is `CERT_SYNC_FAIL_BACKOFF_SECONDS` (default 60); use `restart: on-failure` |
| New domains not in cert | Restart the service (or wait for `CHECK_INTERVAL_SECONDS`) |
| Unhealthy container | Leaf/provider missing or cert expired (`HEALTHCHECK` uses `checkend 0`) |
