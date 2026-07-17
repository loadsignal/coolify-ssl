# coolify-ssl

[![CI](https://github.com/loadsignal/coolify-ssl/actions/workflows/ci.yml/badge.svg)](https://github.com/loadsignal/coolify-ssl/actions/workflows/ci.yml)

Local TLS for [Coolify](https://coolify.io) + Traefik with a persistent [mkcert](https://github.com/FiloSottile/mkcert) CA. Issues a leaf cert, writes Traefik’s file provider, and can sync that leaf to peer hosts over SSH.

**Private LAN / VPN only** — not a public CA. See [SECURITY.md](./SECURITY.md).

Image: [`ghcr.io/loadsignal/coolify-ssl:0.1.0`](https://ghcr.io/loadsignal/coolify-ssl) (pin a version; never `:latest`).

Full reference: **[docs/guide.md](./docs/guide.md)** · least-privilege sync: **[docs/ssh-least-privilege.md](./docs/ssh-least-privilege.md)**

---

## 1. Quick start (Docker Compose)

1. In Coolify, create a **Docker Compose** resource on the proxy server.
2. Paste [`docker-compose.example.yml`](./docker-compose.example.yml) (or use [`docker-compose.coolify.yml`](./docker-compose.coolify.yml) to build from this repo).
3. Configure domains (env **or** file — pick one).
4. Deploy. Then install `/data/coolify/ca/rootCA.pem` on clients (see [guide](./docs/guide.md#trusting-the-ca)).

### Domains via `SSL_DOMAINS`

Coolify → Environment Variables:

```env
SSL_DOMAINS=coolify.lan,*.tools.lan,10.0.0.4
```

Comma-separated SANs. After changing domains, **restart** the service.

### Domains via file

Coolify → File Mount at `/etc/ssl-gen/domains.txt` (wins when non-empty). Format: [`domains.example.txt`](./domains.example.txt).

```text
coolify.lan
*.tools.lan
# 10.0.0.4
```

After editing the file, **restart** the service.

Minimal compose shape:

```yaml
services:
  coolify-ssl:
    image: ghcr.io/loadsignal/coolify-ssl:0.1.0
    restart: on-failure:5
    environment:
      SSL_DOMAINS: ${SSL_DOMAINS:-}
    volumes:
      - /data/coolify/ca:/caroot
      - /data/coolify/proxy/certs:/certs
      - /data/coolify/proxy/dynamic:/dynamic
```

---

## 2. Sync the leaf to another server

On the **source** Coolify host (the one running coolify-ssl):

1. Mount **one** Coolify SSH key into the compose service and set sync env:

```env
CERT_SYNC_HOSTS=10.0.0.5
CERT_SYNC_SSH_KEY_PATH=/run/coolify-ssl/sync.key
```

```yaml
volumes:
  # …existing mounts…
  - /data/coolify/ssh/keys/ssh_key@<uuid>:/run/coolify-ssl/sync.key:ro
```

2. Seed peer host keys (required — no TOFU):

```bash
ssh-keyscan -H 10.0.0.5 >> /data/coolify/ca/ssh_known_hosts
```

3. **Restart** coolify-ssl.

Prefer a dedicated sync user instead of `root` — [docs/ssh-least-privilege.md](./docs/ssh-least-privilege.md).

---

## License

MIT
