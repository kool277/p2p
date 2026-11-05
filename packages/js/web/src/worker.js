// Runs in a Web Worker. It answers the core's transport commands with WebSocket and
// RTCDataChannel, keeps opaque blobs in IndexedDB, and turns operations into promises.
// There is no protocol logic here and no key material: frames are already encrypted when
// they reach this file, and the identity stays inside WebAssembly.

import init, { Client, Identity, conformanceRun, newWrappingKey, providerName } from "../wasm/qalqon_wasm.js";

const WS_CAPS = JSON.stringify({ ordered: true, reliable: true, maxFrameLen: 65553 });
// RTCDataChannel's safe message size across browsers.
const DATA_CHANNEL_CAPS = JSON.stringify({ ordered: true, reliable: true, maxFrameLen: 16000 });

let client = null;
let identity = null;
let profile = "default";
const links = new Map();
const pendingOps = new Map();
const eventQueue = [];
const eventWaiters = [];
const messageWaiters = [];
let timer = null;

// ---------------------------------------------------------------- IndexedDB

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("qalqon", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("profiles");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadProfile(name) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction("profiles").objectStore("profiles").get(name);
    request.onsuccess = () => resolve(request.result ?? {});
    request.onerror = () => reject(request.error);
  });
}

async function saveProfile(name, changes) {
  const db = await openDb();
  const current = await loadProfile(name);
  return new Promise((resolve, reject) => {
    const tx = db.transaction("profiles", "readwrite");
    tx.objectStore("profiles").put({ ...current, ...changes }, name);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function openIdentity() {
  const stored = await loadProfile(profile);
  if (stored.wrappingKey && stored.wrappedIdentity) {
    return Identity.open(stored.wrappingKey, stored.wrappedIdentity);
  }
  const wrappingKey = await newWrappingKey();
  const created = await Identity.create(wrappingKey);
  await saveProfile(profile, { wrappingKey, wrappedIdentity: created.wrapped });
  return created.takeIdentity();
}

// ---------------------------------------------------------------- bytes

function toBase64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(text);
}

function fromBase64(text) {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------- transports

function openWebSocket(linkId, url) {
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  links.set(linkId, { send: (bytes) => socket.send(bytes), close: () => socket.close() });
  socket.onopen = () => {
    client.linkOpened(linkId, WS_CAPS);
    pump();
  };
  socket.onmessage = (event) => {
    client.frameReceived(linkId, new Uint8Array(event.data));
    pump();
  };
  socket.onclose = () => {
    if (links.delete(linkId)) {
      client.linkClosed(linkId);
      pump();
    }
  };
}

// A direct path between two browsers. One blob per side, with ICE gathered up front. A
// native peer offers TCP candidates here instead, which a browser cannot dial, so it
// reports the link closed and the core falls back to the relay.
function openPeerLink(linkId, initiator) {
  const connection = new RTCPeerConnection({ iceServers: [] });
  const link = {
    send: () => {},
    close: () => connection.close(),
    onSignal: async (blob) => {
      const signal = JSON.parse(new TextDecoder().decode(blob));
      if (!signal.sdp) {
        closePeerLink();
        return;
      }
      await connection.setRemoteDescription(signal.sdp);
      if (!initiator) {
        await connection.setLocalDescription(await connection.createAnswer());
        await gathered(connection);
        client.signalReceived(linkId, new TextEncoder().encode(JSON.stringify({ sdp: connection.localDescription })));
        pump();
      }
    },
  };
  links.set(linkId, link);
  const closePeerLink = () => {
    if (links.delete(linkId)) {
      connection.close();
      client.linkClosed(linkId);
      pump();
    }
  };
  const useChannel = (channel) => {
    channel.binaryType = "arraybuffer";
    link.send = (bytes) => channel.send(bytes);
    channel.onopen = () => {
      client.linkOpened(linkId, DATA_CHANNEL_CAPS);
      pump();
    };
    channel.onmessage = (event) => {
      client.frameReceived(linkId, new Uint8Array(event.data));
      pump();
    };
    channel.onclose = closePeerLink;
  };
  if (initiator) {
    useChannel(connection.createDataChannel("qalqon"));
    connection
      .createOffer()
      .then((offer) => connection.setLocalDescription(offer))
      .then(() => gathered(connection))
      .then(() => {
        client.signalReceived(linkId, new TextEncoder().encode(JSON.stringify({ sdp: connection.localDescription })));
        pump();
      })
      .catch(closePeerLink);
  } else {
    connection.ondatachannel = (event) => useChannel(event.channel);
  }
}

function gathered(connection) {
  if (connection.iceGatheringState === "complete") {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    connection.addEventListener("icegatheringstatechange", () => {
      if (connection.iceGatheringState === "complete") {
        resolve();
      }
    });
    setTimeout(resolve, 1000);
  });
}

function perform(command) {
  switch (command.type) {
    case "openLink":
      if (command.kind === "peer") {
        if (typeof RTCPeerConnection === "undefined") {
          // Workers have no WebRTC in most browsers, so this path falls back to the relay.
          queueMicrotask(() => {
            client.linkClosed(command.linkId);
            pump();
          });
        } else {
          openPeerLink(command.linkId, command.initiator);
        }
      } else {
        openWebSocket(command.linkId, command.url);
      }
      break;
    case "sendFrame":
      links.get(command.linkId)?.send(fromBase64(command.frame));
      break;
    case "sendSignal":
      links.get(command.linkId)?.onSignal?.(fromBase64(command.blob));
      break;
    case "closeLink": {
      const link = links.get(command.linkId);
      if (link) {
        links.delete(command.linkId);
        link.close();
      }
      break;
    }
  }
}

// ---------------------------------------------------------------- the main loop

function settle() {
  for (const [op, { resolve, reject }] of pendingOps) {
    const done = client.takeCompletion(op);
    if (done !== undefined) {
      pendingOps.delete(op);
      const result = JSON.parse(done);
      if (result.error) {
        reject(result.error);
      } else {
        resolve(result.ok);
      }
    }
  }
}

function pump() {
  if (!client) {
    return;
  }
  client.drive();
  for (;;) {
    const command = client.pollCommand();
    if (command === undefined) {
      break;
    }
    perform(JSON.parse(command));
  }
  for (;;) {
    const event = client.pollEvent();
    if (event === undefined) {
      break;
    }
    const parsed = JSON.parse(event);
    const waiter = eventWaiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(parsed);
    } else {
      eventQueue.push(parsed);
    }
  }
  // Anyone waiting on a message may have one now.
  for (const waiter of messageWaiters.splice(0)) {
    waiter();
  }
  settle();
  const saved = client.takeStateToSave();
  if (saved !== undefined) {
    saveProfile(profile, { saved });
  }
  if (timer !== null) {
    clearTimeout(timer);
  }
  const next = client.handleTimeout();
  settle();
  const delay = next === undefined ? 1000 : Math.min(1000, Math.max(5, next - Date.now()));
  timer = setTimeout(pump, delay);
}

function waitOp(op) {
  return new Promise((resolve, reject) => {
    pendingOps.set(op, { resolve, reject });
    pump();
  });
}

function apiError(name) {
  return { code: 0, name: String(name) };
}

async function makeClient(config, needChain) {
  profile = config.dataDir ?? "default";
  await init();
  identity = identity ?? (await openIdentity());
  const stored = await loadProfile(profile);
  if (needChain && !stored.chain) {
    throw { code: 304, name: "notEnrolled" };
  }
  client = new Client(JSON.stringify(config), identity, stored.chain, stored.saved);
}

const methods = {
  async providerName() {
    await init();
    return providerName();
  },

  async conformanceRun({ vectors }) {
    await init();
    return JSON.parse(conformanceRun(vectors));
  },

  async enrollDevice({ config, request }) {
    await makeClient(config, false);
    const result = await waitOp(client.startEnroll(JSON.stringify(request)));
    await saveProfile(profile, { chain: fromBase64(result.chain) });
    await waitOp(client.close());
    client = null;
    return result.enrolled;
  },

  async connect({ config, credentials }) {
    await makeClient(config, true);
    await waitOp(client.startConnect(JSON.stringify(credentials)));
    return null;
  },

  async openChannel({ peer, options }) {
    return (await waitOp(client.openChannel(JSON.stringify(peer), JSON.stringify(options)))).channelId;
  },

  async acceptChannel({ requestId }) {
    return (await waitOp(client.acceptChannel(requestId))).channelId;
  },

  rejectChannel({ requestId }) {
    client.rejectChannel(requestId);
    pump();
    return null;
  },

  verifyPeer({ peer, safetyNumber }) {
    const result = JSON.parse(client.verifyPeer(JSON.stringify(peer), safetyNumber ?? undefined));
    pump();
    return result;
  },

  async rotateKeys({ peer }) {
    await waitOp(client.rotateKeys(peer ? JSON.stringify(peer) : undefined));
    return null;
  },

  exportAudit({ request }) {
    return JSON.parse(client.exportAudit(JSON.stringify(request ?? {})));
  },

  nextEvent({ timeoutMs }) {
    const queued = eventQueue.shift();
    if (queued) {
      return queued;
    }
    if (!timeoutMs) {
      return null;
    }
    return new Promise((resolve) => {
      const waiter = { resolve, timer: 0 };
      waiter.timer = setTimeout(() => {
        const index = eventWaiters.indexOf(waiter);
        if (index >= 0) {
          eventWaiters.splice(index, 1);
        }
        resolve(null);
      }, timeoutMs);
      eventWaiters.push(waiter);
    });
  },

  async close() {
    await waitOp(client.close());
    pump();
    return null;
  },

  send({ channelId, payload }) {
    client.send(channelId, payload);
    pump();
    return null;
  },

  async receive({ channelId, timeoutMs }) {
    const deadline = Date.now() + (timeoutMs ?? 0);
    for (;;) {
      const message = client.receive(channelId);
      if (message !== undefined) {
        return message;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return null;
      }
      await new Promise((resolve) => {
        const done = () => {
          clearTimeout(wait);
          resolve();
        };
        const wait = setTimeout(() => {
          const index = messageWaiters.indexOf(done);
          if (index >= 0) {
            messageWaiters.splice(index, 1);
          }
          resolve();
        }, remaining);
        messageWaiters.push(done);
      });
    }
  },

  channelInfo({ channelId }) {
    return JSON.parse(client.channelInfo(channelId));
  },

  async closeChannel({ channelId }) {
    await waitOp(client.closeChannel(channelId));
    return null;
  },
};

self.onmessage = async ({ data: { id, method, params } }) => {
  try {
    const result = await methods[method](params ?? {});
    self.postMessage({ id, result });
  } catch (error) {
    const reported = typeof error === "object" && error !== null && "name" in error ? error : apiError(error);
    self.postMessage({ id, error: { code: reported.code ?? 0, name: reported.name, message: String(reported.message ?? reported.name) } });
  }
};
