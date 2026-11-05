# infra/relay

The blind relay. It pairs two clients that hold grants for one rendezvous, then forwards frames it cannot read. It holds no session keys. Its only secret is the key it shares with the server for checking grants.

```sh
qalqon-relay --listen 127.0.0.1:9100 --relay-key file:/path/to/keys#relay
```

An interop run checks that application data never appears in what it forwards.
