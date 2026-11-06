#!/usr/bin/env bash
# Runs the shared vectors through the shell client, against a qalqond it starts itself.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$PWD/target/debug:$PATH"
directory=$(mktemp -d)
chmod 700 "$directory"
socket="$directory/qalqond.sock"
qalqond serve --socket "$socket" 2>/dev/null &
daemon=$!
cleanup() {
  qalqon_stop
  kill "$daemon" 2>/dev/null
  rm -rf "$directory"
}
trap cleanup EXIT
for _ in $(seq 500); do [ -S "$socket" ] && break; sleep 0.01; done
# shellcheck disable=SC1091
source "$here/qalqon.sh"
qalqon_start "$socket"
failed=0
for file in "$@"; do
  report=$(qalqon_conformance_run "$(jq -Rs . <"$file")" | jq -r .)
  passed=$(jq -r .passed <<<"$report")
  count=$(jq -r '.failed | length' <<<"$report")
  echo "$(basename "$file"): $passed passed, $count failed"
  if [ "$count" != 0 ] || [ "$passed" = 0 ]; then failed=1; fi
done
exit "$failed"
