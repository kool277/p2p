# The ProVerif toolchain for the handshake model, pinned so CI and laptops agree.
FROM ocaml/opam:debian-12-ocaml-4.14
RUN opam update -y && opam install -y proverif.2.05 && sudo cp "$(opam var bin)/proverif" /usr/local/bin/proverif
WORKDIR /model
ENTRYPOINT ["proverif"]
