#!/bin/sh
# Creates a development PKI on first start, then runs the host.
set -eu
if [ ! -f /pki/root.cert ]; then
  /app/qalqon-ca init /pki
  /app/qalqon-ca server /pki localhost
  head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' >/pki/admin.token
  chmod 600 /pki/admin.token
fi
exec /app/qalqon-axum --listen 0.0.0.0:8443 --db /data/host.sqlite --pki /pki --host localhost \
  --relay "${RELAY_URL:-ws://127.0.0.1:9100/}" --admin-token-file /pki/admin.token
