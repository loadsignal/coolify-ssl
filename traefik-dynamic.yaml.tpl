# Rendered by generate-certs.sh into Traefik's dynamic dir. Do not edit on the host.
# /traefik/certs is Coolify's proxy cert mount inside Traefik.
tls:
  certificates:
    - certFile: /traefik/certs/__CERT_NAME__.cert
      keyFile: /traefik/certs/__CERT_NAME__.key
