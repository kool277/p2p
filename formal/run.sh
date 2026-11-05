#!/usr/bin/env bash
# Runs every model and compares each RESULT with what the file says it should be.
# A query that comes back "cannot be proved" fails this script.
set -u
cd "$(dirname "$0")"
TIME_LIMIT=${MODEL_TIMEOUT:-1800}
# The limit runs inside the container, so a run that hits it really stops.
PROVERIF=${PROVERIF:-"docker run --rm --init -v $PWD:/model -w /model --entrypoint timeout qalqon-proverif $TIME_LIMIT proverif"}

#            file                     lib  expected true  expected false
models=(
  "honest_run.pv                      lib  0              2"
  "fs_secrecy_agreement.pv            lib  8              0"
  "ephemeral_leak.pv                  lib  2              0"
  "kci.pv                             lib  2              0"
  "hybrid.pv                          -    2              0"
  "rekey.pv                           -    2              1"
  "pins.pv                            lib  4              1"
  "first_contact.pv                   lib  0              1"
  "negative_ik.pv                     -    0              2"
)

check() {
  local entry=$1 status=0
  read -r file lib want_true want_false <<<"$entry"
  args=()
  [ "$lib" = lib ] && args=(-lib qalqon.pvl)
  start=$(date +%s)
  output=$($PROVERIF "${args[@]}" "$file" 2>&1)
  rc=$?
  took=$(( $(date +%s) - start ))
  results=$(grep -E '^RESULT ' <<<"$output")
  got_true=$(grep -c ' is true\.$' <<<"$results")
  got_false=$(grep -c ' is false\.$' <<<"$results")
  unknown=$(grep -c 'cannot be proved' <<<"$results")
  if [ "$rc" -ne 0 ] || [ "$got_true" != "$want_true" ] || [ "$got_false" != "$want_false" ] || [ "$unknown" != 0 ]; then
    echo "FAIL $file (${took}s): true=$got_true/$want_true false=$got_false/$want_false unknown=$unknown rc=$rc"
    if [ -n "$results" ]; then sed 's/^/  /' <<<"$results"; else tail -8 <<<"$output" | sed 's/^/  /'; fi
    status=1
  else
    echo "ok   $file (${took}s): $got_true proved, $got_false refuted as expected"
  fi
  return $status
}

pids=()
for entry in "${models[@]}"; do
  check "$entry" &
  pids+=($!)
done
status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=1
done
exit $status
