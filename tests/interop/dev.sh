#!/usr/bin/env bash
# `qalqon dev`: runs the host and the relay on loopback, with a fresh development PKI, until
# you press Ctrl-C. Nothing here is hardened, and the crypto provider is the test-only one.
set -euo pipefail
cd "$(dirname "$0")/../.."
server=${1:-rust-axum}
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$work"' EXIT
BIN=target/debug
$BIN/qalqon-ca init "$work/pki"
$BIN/qalqon-ca server "$work/pki" 127.0.0.1
head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$work/admin.token"
chmod 600 "$work/admin.token"
$BIN/qalqon-relay --listen 127.0.0.1:9100 --relay-key "file:$work/pki/keys#relay" &
$BIN/qalqon-axum --listen 127.0.0.1:8443 --db "$work/host.sqlite" --pki "$work/pki" --host 127.0.0.1 \
  --relay ws://127.0.0.1:9100/ --admin-token-file "$work/admin.token" &
cat <<EOM

Host:        ws://127.0.0.1:8443/qalqon
Relay:       ws://127.0.0.1:9100/
CA bundle:   $work/pki/root.cert
Admin token: $work/admin.token

Create a user:
  curl -X POST -H "Authorization: Bearer \$(cat $work/admin.token)" \\
       -d '{"user_id":"alice","password":"correct horse battery staple"}' \\
       http://127.0.0.1:8443/admin/users.create
EOM
wait
