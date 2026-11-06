# Shortcuts to the qalqon CLI. No build logic lives here (ADR-0003).

default:
    @just --list

list:
    cargo qalqon list

doctor:
    cargo qalqon doctor

lint:
    cargo qalqon lint

build client server:
    cargo qalqon build --client {{client}} --server {{server}}

dev client server:
    cargo qalqon dev --client {{client}} --server {{server}}

pair client server:
    cargo qalqon test --pair {{client}}:{{server}}

triple a b server:
    cargo qalqon test --triple {{a}},{{b}}:{{server}}

conformance binding:
    cargo qalqon test --conformance {{binding}}

primary:
    cargo qalqon test --primary

generate:
    cargo run -q -p idlgen
    cargo run -q -p vectors -- write tests/conformance/testonly
    cargo qalqon manifests

check-generated:
    cargo run -q -p idlgen -- --check
    cargo run -q -p vectors -- check tests/conformance/testonly
    cargo qalqon manifests --check

proofs:
    docker build -q -t qalqon-proverif formal
    formal/run.sh
