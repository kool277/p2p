# clients/php-cli

A command-line client in PHP, over the `qalqond` sidecar. There is no cryptography here: the keys and all protocol logic stay inside the daemon. Set `QALQOND_SOCKET` to the daemon's socket.

```sh
cargo qalqon test --pair php-cli:rust-axum
```
