#!/usr/bin/env bash
# Runs every model and compares each RESULT with what the file says it should be.
# A query that comes back "cannot be proved" fails this script.
set -u
cd "$(dirname "$0")"
PROVERIF=${PROVERIF:-"docker run --rm -v $PWD:/model -w /model --entrypoint proverif qalqon-proverif"}

#            file                     lib  expected true  expected false
models=(
  "fs_secrecy_agreement.pv            lib  8              2"
  "ephemeral_leak.pv                  lib  2              1"
  "kci.pv                             lib  2              2"
  "hybrid.pv                          -    2              0"
  "rekey.pv                           -    2              1"
  "pins.pv                            lib  4              1"
  "first_contact.pv                   lib  0              1"
  "negative_ik.pv                     -    0              2"
)

status=0
for entry in "${models[@]}"; do
  read -r file lib want_true want_false <<<"$entry"
  args=()
  [ "$lib" = lib ] && args=(-lib qalqon.pvl)
  start=$(date +%s)
  output=$(timeout "${MODEL_TIMEOUT:-900}" $PROVERIF "${args[@]}" "$file" 2>&1)
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
done
exit $status
