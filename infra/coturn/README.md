# coturn

TURN relays WebRTC traffic when NAT traversal fails, and sees only ciphertext.

```sh
docker run --rm --network host -v "$PWD/infra/coturn/turnserver.conf:/etc/coturn/turnserver.conf" coturn/coturn:4.6.3
```

**Status:** this config has never been started, and no interop run exercises TURN yet. `@qalqon/web` accepts `iceServers`. Native clients do not speak WebRTC yet, so they use `infra/relay` instead.
