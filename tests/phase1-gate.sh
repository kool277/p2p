#!/usr/bin/env bash
# The Phase 1 gate: two Rust peers, as separate processes, interoperate over TCP and
# UDP, on the test-only provider. This does not meet the gate's requirement of
# known-answer tests from the official control examples. See PLAN.md.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p qalqon-ca -p peer-demo
BIN=target/debug
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
$BIN/qalqon-ca init "$work"
$BIN/qalqon-ca device "$work" alice a1
$BIN/qalqon-ca device "$work" bob b1

run_pair() {
  local name=$1 transport=$2 port=$3
  shift 3
  $BIN/peer-demo listen "$transport" "127.0.0.1:$port" "$work" bob/b1 alice/a1 "$@" >"$work/$name.r" 2>&1 &
  local listener=$!
  sleep 0.3
  local i_status=0 r_status=0
  $BIN/peer-demo connect "$transport" "127.0.0.1:$port" "$work" alice/a1 bob/b1 "$@" >"$work/$name.i" 2>&1 || i_status=$?
  wait "$listener" || r_status=$?
  echo "$name initiator: $(cat "$work/$name.i")"
  echo "$name responder: $(cat "$work/$name.r")"
  if [ "$i_status" != 0 ] || [ "$r_status" != 0 ]; then
    echo "FAILED: $name (initiator $i_status, responder $r_status)"
    return 1
  fi
  # Both processes must report the same session, which only holds if they derived the
  # same transcript and keys.
  local i_id r_id
  i_id=$(sed -n 's/.*"session_id":"\([0-9a-f]*\)".*/\1/p' "$work/$name.i")
  r_id=$(sed -n 's/.*"session_id":"\([0-9a-f]*\)".*/\1/p' "$work/$name.r")
  if [ -z "$i_id" ] || [ "$i_id" != "$r_id" ]; then
    echo "FAILED: $name session ids differ: $i_id / $r_id"
    return 1
  fi
}

run_pair tcp-1000-records-with-rekey tcp 47011 --records 1000 --rekey-after 64
run_pair udp-1000-records-with-rekey udp 47012 --records 1000 --rekey-after 64
run_pair udp-with-10-percent-loss    udp 47013 --records 1000 --rekey-after 64 --loss 10
echo "gate passed: two processes interoperated over TCP and UDP"
