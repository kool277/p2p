#!/usr/bin/env bash
# Runs one model and prints its results, for working on it.
cd "$(dirname "$0")"
lib=(-lib qalqon.pvl)
grep -q "^free c: channel" "$1" && lib=()
exec docker run --rm --init -v "$PWD:/model" -w /model --entrypoint timeout qalqon-proverif "${MODEL_TIMEOUT:-1800}" proverif "${lib[@]}" "$1"
