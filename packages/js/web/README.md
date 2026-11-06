# @qalqon/web

The Qalqon SDK for browsers. Names and error codes match every other language (`docs/SDK-API.md`). The core runs as WebAssembly in a Web Worker, so keys and protocol logic stay off the main thread.

```js
import { createClient, hexToBase64 } from "@qalqon/web";

const client = createClient();
const session = await client.connect(
  { serverUrl, caBundle: hexToBase64(caHex), keyStore: { kind: "osDefault" }, dataDir: "profile-1" },
  { userId: "alice", secret: password },
);
const channel = await session.openChannel({ userId: "bob" }, { label: "chat", ordered: true, reliable: true });
await channel.send("hello");
```

Build the WebAssembly first: see `bindings/wasm/README.md`. WebRTC runs on the page, because it does not exist inside a Worker, and it only sees frames that are already encrypted.
