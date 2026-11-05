// The Qalqon SDK for browsers. Method names and error codes are the same as in every other
// language (docs/SDK-API.md). The work happens in a Web Worker.

export class QalqonError extends Error {
  constructor({ code, name }) {
    super(name);
    this.name = "QalqonError";
    this.errorName = name;
    this.code = code;
  }
}

function toBytes(value) {
  return typeof value === "string" ? new TextEncoder().encode(value) : value;
}

function base64(bytes) {
  let text = "";
  for (const byte of bytes) {
    text += String.fromCharCode(byte);
  }
  return btoa(text);
}

/** Decodes hex text, for a CA bundle held as a file. */
export function hexToBase64(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return base64(bytes);
}

class Rpc {
  constructor(worker) {
    this.worker = worker;
    this.next = 1;
    this.pending = new Map();
    worker.onmessage = ({ data: { id, result, error } }) => {
      const pending = this.pending.get(id);
      this.pending.delete(id);
      if (error) {
        pending.reject(new QalqonError(error));
      } else {
        pending.resolve(result);
      }
    };
    worker.onerror = (event) => {
      for (const pending of this.pending.values()) {
        pending.reject(new QalqonError({ code: 6, name: `internal: ${event.message}` }));
      }
      this.pending.clear();
    };
  }

  call(method, params, transfer) {
    return new Promise((resolve, reject) => {
      const id = this.next++;
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, method, params }, transfer ?? []);
    });
  }
}

export class Channel {
  constructor(rpc, channelId) {
    this.rpc = rpc;
    this.channelId = channelId;
  }

  /** `channel.send`. A string is sent as UTF-8. */
  send(payload) {
    return this.rpc.call("send", { channelId: this.channelId, payload: toBytes(payload) });
  }

  /** `channel.receive`. Resolves to a Uint8Array, or to null if the timeout passes first. */
  receive(timeoutMs = 0) {
    return this.rpc.call("receive", { channelId: this.channelId, timeoutMs });
  }

  /** `channel.info`. */
  info() {
    return this.rpc.call("channelInfo", { channelId: this.channelId });
  }

  /** `channel.close`. */
  close() {
    return this.rpc.call("closeChannel", { channelId: this.channelId });
  }
}

export class Session {
  constructor(rpc) {
    this.rpc = rpc;
  }

  /** `session.openChannel`. */
  async openChannel(peer, options) {
    return new Channel(this.rpc, await this.rpc.call("openChannel", { peer, options }));
  }

  /** `session.acceptChannel`. */
  async acceptChannel(requestId) {
    return new Channel(this.rpc, await this.rpc.call("acceptChannel", { requestId }));
  }

  /** `session.rejectChannel`. */
  rejectChannel(requestId) {
    return this.rpc.call("rejectChannel", { requestId });
  }

  /** `session.verifyPeer`. */
  verifyPeer(peer, safetyNumber = null) {
    return this.rpc.call("verifyPeer", { peer, safetyNumber });
  }

  /** `session.rotateKeys`. */
  rotateKeys(peer = null) {
    return this.rpc.call("rotateKeys", { peer });
  }

  /** `session.exportAudit`. `events` in the result is base64, like every bytes field. */
  exportAudit(request = {}) {
    return this.rpc.call("exportAudit", { request });
  }

  /** `session.nextEvent`. Resolves to an event, or to null if the timeout passes first. */
  nextEvent(timeoutMs = 0) {
    return this.rpc.call("nextEvent", { timeoutMs });
  }

  /** `session.close`. */
  close() {
    return this.rpc.call("close");
  }
}

/**
 * Creates a client with its own worker. Bundlers need the worker's URL to appear here
 * literally, so the default stays in this file.
 */
export function createClient(worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" })) {
  const rpc = new Rpc(worker);
  return {
    /** `enrollDevice`. */
    enrollDevice: (config, request) => rpc.call("enrollDevice", { config, request }),
    /** `connect`. */
    connect: async (config, credentials) => {
      await rpc.call("connect", {
        config,
        credentials: { ...credentials, secret: base64(toBytes(credentials.secret)) },
      });
      return new Session(rpc);
    },
    /** `conformanceRun`. */
    conformanceRun: (vectors) => rpc.call("conformanceRun", { vectors }),
    /** The crypto provider's name. A test-only build says so. */
    providerName: () => rpc.call("providerName"),
  };
}
