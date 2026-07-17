# Security Policy

## Supported versions

Security fixes are applied on the latest `main` and the newest `v*` release tag.

## Reporting a vulnerability

Open a [private GitHub security advisory](https://github.com/loadsignal/coolify-ssl/security/advisories/new) on this repository.

Include:

- Affected version / commit
- Reproduction steps
- Impact assessment

Do not open a public issue for unpatched vulnerabilities that allow CA/key theft or remote code execution via sync.

## Threat model (lab / self-hosted LAN only)

**coolify-ssl is not a public certificate authority and is not suitable for internet-facing production TLS.**

It is intended for:

- Private Coolify / Traefik setups on a LAN or VPN
- Internal `.lan` / `.home.arpa` / similar names without public ACME
- Developer trust stores

It is **not** intended for:

- Public websites or any service exposed to the open internet
- Compliance-sensitive or multi-tenant production PKI
- Replacing Let’s Encrypt / ACME for publicly trusted certificates

## Trust boundaries

| Asset | Risk if compromised |
|-------|---------------------|
| `rootCA-key.pem` | Attacker can mint trusted certs for any name your clients trust |
| Leaf `*.key` | Impersonation of that Traefik vhost until rotated |
| Coolify SSH key used for sync | Remote write to peer proxy cert/dynamic dirs (often as `root`) |
| `ssh_known_hosts` | Wrong entries enable MITM on leaf distribution |

**Never distribute the CA private key.** Only `rootCA.pem` should be installed on client machines.

## Runtime privileges

The container runs as **root** because Coolify’s proxy cert and dynamic directories on the host are typically root-owned. A non-root user would fail to write unless you chown those mounts. Treat the container as high privilege: it can write proxy TLS material and, when sync is enabled, read the bind-mounted sync key.

**Mount one Coolify SSH key file** for leaf sync (e.g. `ssh_key@<uuid>:/run/coolify-ssl/sync.key:ro`). Do **not** mount the entire `/data/coolify/ssh/keys` directory — that would expose every Coolify-managed private key to this container. `CERT_SYNC_SSH_KEY_PATH` must resolve under `/run/coolify-ssl/`; legacy full-directory remaps are rejected at runtime.

Prefer a **dedicated sync user** on peers instead of `root` — see [docs/ssh-least-privilege.md](./docs/ssh-least-privilege.md). Default `CERT_SYNC_SSH_USER=root` exists only for Coolify convenience; when sync is enabled with that default, coolify-ssl logs a **WARNING** at startup.

The SSH private key used for sync is copied to `/run/coolify-ssl/cert-sync-key` (directory mode `700`, key mode `600`), not world-writable `/tmp`.

## Single writer

Only **one** coolify-ssl process may write a given cert volume. At startup the entrypoint takes a non-blocking lock on `LOCK_FILE` (default `$CERT_DIR/.coolify-ssl.lock`): `flock` in the Alpine image (released when the process exits), or a mkdir lock directory when `flock` is unavailable. A second instance exits with a fatal error instead of racing leaf publish / Traefik provider updates. Do not run two coolify-ssl services against the same `/certs` (or `/dynamic`) mounts.

## CA bootstrap trust stores

`mkcert -install` creates the CA under `CAROOT` and optionally installs it into local trust stores. Unset `TRUST_STORES` means “all stores” in mkcert. coolify-ssl defaults `TRUST_STORES=java` (image `ENV` + runtime fallback) so bootstrap writes `/caroot` material without mutating system/NSS stores. Clients still install `rootCA.pem` explicitly. Override `TRUST_STORES` only if you intentionally want host trust-store installation.

## Leaf publish atomicity

Local and remote leaf publish use a **generation + symlink flip**:

1. Write `cert` + `key` into `CERT_DIR/.gen.<id>/`
2. Ensure stable names `CERT_NAME.cert` / `.key` are symlinks to `.leaf/...`
3. Flip `CERT_DIR/.leaf` → `.gen.<id>` with `ln -sfn` (pair becomes visible together)
4. Write the Traefik provider **last** (with a `generated-at` stamp) so file-watch reload re-reads the cert paths

Pre-existing flat files are migrated into this layout on startup. Traefik keeps the same Coolify paths (`/traefik/certs/…`). CI runs `tests/traefik-smoke/` to prove HTTPS through this layout before and after a SAN-driven renew.

Peers execute the same layout logic via `lib/remote-publish.sh` (copied per sync). Generation prune skips symlinks so a planted `.gen.*` link cannot redirect `rm -rf` outside the cert dir.

## SSH leaf sync

When `CERT_SYNC_HOSTS` is set:

1. Host keys are verified with **`StrictHostKeyChecking=yes`** against a **persisted** known_hosts file (default `/caroot/ssh_known_hosts` on the CA volume).
2. TOFU / `accept-new` is **not** used. Seed keys before enabling sync:

   ```bash
   # On the Coolify host (path must match your CA volume mount)
   ssh-keyscan -H 10.0.0.5 >> /data/coolify/ca/ssh_known_hosts
   ```

3. Remote commands quote paths safely; `CERT_NAME`, remote dirs, domains, and sync hosts are validated (hostname / IPv4 for sync peers; SANs also allow IPv6 and `*.a.b` wildcards). `CERT_SYNC_HOSTS` accepts spaces or commas.
4. Leaf + provider + `lib/remote-publish.sh` are staged via scp, then the peer runs that script (atomic `.leaf` generation flip; provider last). The remote command is no longer an opaque one-liner.
5. Sync runs **every check cycle** when `CERT_SYNC_HOSTS` is set (including when the local leaf was not re-issued). A peer is **skipped** when its remote leaf cert DER SHA-256 already matches the local leaf (requires `openssl` on the remote; if openssl is missing the check fails open and sync proceeds).
6. Default SSH user is **`root`** (Coolify convention). Prefer a dedicated least-privilege account — see [docs/ssh-least-privilege.md](./docs/ssh-least-privilege.md).
7. **`CERT_SYNC_STRICT` defaults to `1`**: any failed peer sync aborts the process after `CERT_SYNC_FAIL_BACKOFF_SECONDS` (default `60`) so Docker restart loops do not hammer peers. Set backoff to `0` only for tests. Prefer `restart: on-failure` in compose. Set `CERT_SYNC_STRICT=0` only if you deliberately want local renewals to succeed while remotes lag.
8. Failed mid-flight syncs best-effort remove remote staging files, aborted `.gen.*` dirs, and the staged publish script. Generation prune refuses to follow symlinks (`rm -rf` only on real directories).
9. Hybrid leaf layout (one of the stable cert/key paths is a symlink and the other is not) fails at startup migrate instead of leaving an inconsistent state.

## Input validation

`CERT_NAME`, `PROVIDER_FILE`, remote paths, domains/SANs, sync hosts, `CHECK_INTERVAL_SECONDS` and `RENEW_BEFORE_EXPIRY_SECONDS` (integers `60`–`315360000`; legacy `RENEW_INTERVAL_SECONDS` fills both when unset), and `MAX_DOMAINS` (integer `1`–`256`, default `64`) are validated. Domain checks reject shell metacharacters and invalid IPv4/IPv6/host labels (IPv6 hextet count and length are enforced). SAN equality for renewal uses canonical IPv6 (expanded), IPv4, and lowercased DNS so textual form differences do not force re-issue. This reduces injection risk from misconfiguration and is not a substitute for protecting who can set Coolify environment variables.
