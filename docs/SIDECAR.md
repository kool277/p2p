# The sidecar

`qalqond` serves the SDK API over a local socket, for languages that cannot load a library. It embeds the core, so keys never leave its process. The design is in [ADR-0004](adr/0004-sidecar-ipc.md).

```sh
qalqond serve --socket /run/user/1000/qalqon/qalqond.sock     # a Unix socket in a 0700 directory
qalqond serve --tcp 127.0.0.1:0 --token-file ./token          # loopback TCP with a per-launch token
```

## What it protects against

It protects against other users and remote hosts, and not against malware running as the same user. On Linux it checks the peer's UID with `SO_PEERCRED`. On other Unix systems it relies on the socket's `0700` directory, and `getpeereid` is a recorded gap. Windows named pipes are not built yet.

Plaintext payloads pass through the socket, in the same trust zone as the application.

## Using it from a language

Every method in `docs/SDK-API.md` is a JSON-RPC call, such as `session.openChannel`. Objects are opaque strings that die with the connection. `bytes` are base64. Errors carry the IDL's code and name.

```php
$q = new Qalqon\QalqonClient($socketPath);
$session = $q->connect($config, $credentials);
$channel = $q->session_openChannel($session, ['userId' => 'bob'], ['label' => 'chat', 'ordered' => true, 'reliable' => true]);
$q->channel_send($channel, 'hello');
```

Clients in `bindings/sidecar-clients/` are generated from the IDL:

| Language | Tested |
| --- | --- |
| PHP | Conformance and a full interop run |
| Shell | Conformance. It talks to a `qalqond client` process through named pipes, because `curl` cannot speak the framing |
| Ruby, Elixir | Generated but **not run**, because those runtimes are not on the development machine |

For a language with no generated client, `qalqon new binding --lang <x> --path sidecar` gives a starting point. There is a working template for Python.
