#!/bin/sh
set -eu
while [ ! -f /pki/server-localhost.chain ]; do sleep 1; done
exec /app/qalqon-relay --listen 0.0.0.0:9100 --relay-key file:/pki/keys#relay
