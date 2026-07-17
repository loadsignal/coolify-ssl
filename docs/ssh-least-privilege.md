# SSH leaf sync with least privilege

Coolify’s default peer user is often `root`. That works, but it gives the sync key
far more power than coolify-ssl needs. Prefer a **dedicated account** that can only
write the proxy cert and dynamic directories.

## What the sync key must be allowed to do

On each peer:

1. `scp` leaf material into `$REMOTE_CERT_DIR` (default `/data/coolify/proxy/certs`)
2. `scp` the Traefik provider into `$REMOTE_DYNAMIC_DIR` (default `/data/coolify/proxy/dynamic`)
3. Run a short remote script (`lib/remote-publish.sh`, scp'd by coolify-ssl) that:
   - creates `.gen.<id>/`
   - moves staged files into that generation
   - flips `.leaf` with `ln -sfn`
   - ensures `CERT_NAME.cert` / `.key` are symlinks into `.leaf/`
   - replaces the provider file
4. Run `openssl x509` on the leaf (fingerprint skip)

It must **not** need: Coolify UI access, Docker socket, other SSH keys, or the CA volume.

## Example: dedicated user on a peer

```bash
# On each CERT_SYNC_HOSTS peer (as root, once):
useradd --system --home /var/lib/coolify-ssl-sync --shell /bin/sh coolify-ssl-sync
mkdir -p /var/lib/coolify-ssl-sync/.ssh
chmod 700 /var/lib/coolify-ssl-sync/.ssh

# Ownership for Traefik/Coolify paths (adjust if your layout differs):
chgrp coolify-ssl-sync /data/coolify/proxy/certs /data/coolify/proxy/dynamic
chmod 775 /data/coolify/proxy/certs /data/coolify/proxy/dynamic

# Authorize only the sync pubkey (no-port-forwarding, no-agent-forwarding):
# from="10.0.0.2",restrict ssh-ed25519 AAAA... coolify-ssl-sync
install -m 600 /dev/null /var/lib/coolify-ssl-sync/.ssh/authorized_keys
# paste the public key line, then:
chown -R coolify-ssl-sync:coolify-ssl-sync /var/lib/coolify-ssl-sync
```

Generate a **dedicated** keypair (do not reuse Coolify’s deploy keys):

```bash
ssh-keygen -t ed25519 -f coolify-ssl-sync -N '' -C coolify-ssl-sync
```

Mount **only** that private key into the coolify-ssl container:

```yaml
environment:
  CERT_SYNC_SSH_USER: coolify-ssl-sync
  CERT_SYNC_SSH_KEY_PATH: /run/coolify-ssl/sync.key
volumes:
  - /path/to/coolify-ssl-sync:/run/coolify-ssl/sync.key:ro
```

Seed `known_hosts` as usual (`ssh-keyscan -H … >> /data/coolify/ca/ssh_known_hosts`).

## Hardening extras (optional)

- `from="source-ip"` in `authorized_keys` so only the Coolify proxy host can authenticate
- Separate key per peer if you want blast-radius isolation
- Keep `CERT_SYNC_STRICT=1` so a broken peer aborts instead of silently drifting

## What this does *not* fix

The **coolify-ssl container itself** still runs as root because Coolify’s proxy mounts are
typically root-owned (see `SECURITY.md`). Least-privilege sync reduces remote blast radius;
it does not drop local container privileges.
