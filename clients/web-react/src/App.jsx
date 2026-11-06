// The demo app: the same screens as every other client (docs/CLIENT-ADAPTER.md), with
// automation IDs of the form qalqon-<screen>-<control>. It renders the SDK and nothing else.

import { useEffect, useRef, useState } from "react";
import { hexToBase64 } from "@qalqon/web";
import { useChannel, useQalqonSession } from "@qalqon/react";

const params = new URLSearchParams(location.search);

function id(screen, control) {
  return { "data-testid": `qalqon-${screen}-${control}` };
}

function Field({ screen, control, label, value, onChange, type = "text" }) {
  return (
    <label style={{ display: "block", margin: "4px 0" }}>
      {label}{" "}
      <input {...id(screen, control)} type={type} value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

const record = (n) => `record ${String(n).padStart(6, "0")} ${"x".repeat(64)}`;

/** The interop run that the driver starts: N records and a rekey, over the real SDK. */
async function runCaller(session, channel, peer, records) {
  let sent = 0;
  let received = 0;
  let rekeyed = false;
  const deadline = Date.now() + 120000;
  while (received < records) {
    if (Date.now() > deadline) {
      throw new Error(`only ${received} of ${records} came back`);
    }
    while (sent < records && sent - received < 64) {
      await channel.send(record(sent));
      sent++;
    }
    const message = await channel.receive(50);
    if (message) {
      const text = new TextDecoder().decode(message);
      if (text !== record(received)) {
        throw new Error(`reply ${received} is wrong: ${text}`);
      }
      received++;
    }
    if (!rekeyed && received >= records / 2) {
      await session.rotateKeys(peer);
      rekeyed = true;
    }
  }
  const info = await channel.info();
  const audit = await session.exportAudit({});
  await session.close();
  return {
    result: "ok",
    records: received,
    path: info.path,
    key_epoch: info.keyEpoch,
    peer_status: info.peer.status,
    safety_number: info.peer.safetyNumber,
    audit_entries: atob(audit.events).split("\n").length - 1,
  };
}

async function runAnswerer(session, channel) {
  const info = await channel.info();
  let echoed = 0;
  let ended = "";
  for (;;) {
    let message;
    try {
      message = await channel.receive(200);
    } catch (failure) {
      ended = failure.errorName ?? String(failure);
      break;
    }
    if (message) {
      await channel.send(message);
      echoed++;
    }
  }
  return {
    result: "ok",
    records: echoed,
    path: info.path,
    peer_status: info.peer.status,
    safety_number: info.peer.safetyNumber,
    ended,
  };
}

export function App() {
  const qalqon = useQalqonSession();
  const [serverUrl, setServerUrl] = useState(params.get("server") ?? "");
  const [caHex, setCaHex] = useState(params.get("ca") ?? "");
  const [profile, setProfile] = useState(params.get("profile") ?? "default");
  const [relayOnly, setRelayOnly] = useState(params.get("relayOnly") === "1");
  const [token, setToken] = useState("");
  const [userId, setUserId] = useState("");
  const [password, setPassword] = useState("");
  const [peerUser, setPeerUser] = useState("");
  const [status, setStatus] = useState("");
  const [provider, setProvider] = useState("");
  const [channel, setChannel] = useState(null);
  const [identity, setIdentity] = useState(null);
  const [safety, setSafety] = useState("");
  const [text, setText] = useState("");
  const [info, setInfo] = useState(null);
  const [interop, setInterop] = useState("");
  const [records, setRecords] = useState("1000");
  const [vectors, setVectors] = useState("");
  const [conformance, setConformance] = useState("");
  const answering = useRef(false);
  const chat = useChannel(interop || answering.current ? null : channel);

  useEffect(() => {
    qalqon.client.providerName().then(setProvider);
  }, [qalqon.client]);

  const config = () => ({
    serverUrl,
    caBundle: hexToBase64(caHex.trim()),
    keyStore: { kind: "osDefault" },
    dataDir: profile,
    ...(relayOnly ? { relayPolicy: "relayOnly" } : {}),
  });

  const attempt = async (work) => {
    setStatus("working");
    try {
      setStatus((await work()) ?? "ok");
    } catch (failure) {
      setStatus(`error: ${failure.errorName ?? failure.message ?? failure}`);
    }
  };

  const peer = () => ({ userId: peerUser });

  const startCall = () =>
    attempt(async () => {
      const opened = await qalqon.session.openChannel(peer(), { label: "interop", ordered: true, reliable: true });
      setChannel(opened);
      setInfo(await opened.info());
      return "channel open";
    });

  const accept = (request, then) =>
    attempt(async () => {
      const opened = await qalqon.session.acceptChannel(request.requestId);
      qalqon.dismissRequest(request.requestId);
      setChannel(opened);
      setInfo(await opened.info());
      then?.(opened);
      return "channel open";
    });

  const startInteropCaller = () =>
    attempt(async () => {
      const opened = await qalqon.session.openChannel(peer(), { label: "interop", ordered: true, reliable: true });
      const result = await runCaller(qalqon.session, opened, peer(), Number(records));
      setInterop(JSON.stringify(result));
      return "interop finished";
    });

  // The answering half: accept the first call and echo until the peer closes.
  const [echoMode, setEchoMode] = useState(false);
  useEffect(() => {
    if (!echoMode || !qalqon.session || qalqon.requests.length === 0 || answering.current) {
      return;
    }
    answering.current = true;
    const request = qalqon.requests[0];
    attempt(async () => {
      const opened = await qalqon.session.acceptChannel(request.requestId);
      qalqon.dismissRequest(request.requestId);
      const result = await runAnswerer(qalqon.session, opened);
      setInterop(JSON.stringify(result));
      return "interop finished";
    });
  }, [echoMode, qalqon.requests, qalqon.session]);

  return (
    <main style={{ fontFamily: "sans-serif", maxWidth: 720, margin: "1rem auto", padding: "0 1rem" }}>
      <h1>Qalqon demo</h1>
      <p {...id("app", "provider")}>Provider: {provider || "loading"}</p>
      <p {...id("app", "status")}>{status}</p>
      <p {...id("app", "state")}>{qalqon.state}</p>
      <p {...id("app", "error")}>{qalqon.error ?? ""}</p>

      <section>
        <h2>Settings</h2>
        <Field screen="settings" control="server" label="Server" value={serverUrl} onChange={setServerUrl} />
        <Field screen="settings" control="ca" label="CA bundle (hex)" value={caHex} onChange={setCaHex} />
        <Field screen="settings" control="profile" label="Profile" value={profile} onChange={setProfile} />
        <label>
          <input
            {...id("settings", "relay-only")}
            type="checkbox"
            checked={relayOnly}
            onChange={(e) => setRelayOnly(e.target.checked)}
          />{" "}
          Relay only
        </label>
      </section>

      <section>
        <h2>Enrol</h2>
        <Field screen="enrol" control="token" label="Token" value={token} onChange={setToken} />
        <button
          {...id("enrol", "submit")}
          onClick={() =>
            attempt(async () => {
              const result = await qalqon.enroll(config(), { enrollmentToken: token, deviceName: "web-react" });
              return `enrolled ${result.deviceId}`;
            })
          }
        >
          Enrol this browser
        </button>
      </section>

      <section>
        <h2>Log in</h2>
        <Field screen="login" control="user" label="User" value={userId} onChange={setUserId} />
        <Field screen="login" control="password" label="Password" type="password" value={password} onChange={setPassword} />
        <button
          {...id("login", "submit")}
          onClick={() =>
            attempt(async () => {
              await qalqon.connect(config(), { userId, secret: password });
              return "connected";
            })
          }
        >
          Log in
        </button>
      </section>

      {qalqon.session && (
        <>
          <section>
            <h2>Peers</h2>
            <Field screen="peers" control="user" label="Peer" value={peerUser} onChange={setPeerUser} />
            <button {...id("peers", "call")} onClick={startCall}>
              Call
            </button>
            <ul>
              {qalqon.requests.map((request) => (
                <li key={request.requestId}>
                  Call from {request.peer.userId}{" "}
                  <button {...id("peers", "accept")} onClick={() => accept(request)}>
                    Accept
                  </button>{" "}
                  <button
                    {...id("peers", "reject")}
                    onClick={() => {
                      qalqon.session.rejectChannel(request.requestId);
                      qalqon.dismissRequest(request.requestId);
                    }}
                  >
                    Decline
                  </button>
                </li>
              ))}
            </ul>
          </section>

          {channel && (
            <section>
              <h2>Channel</h2>
              <ul {...id("channel", "messages")}>
                {chat.messages.map((message, i) => (
                  <li key={i}>{message}</li>
                ))}
              </ul>
              <Field screen="channel" control="text" label="Message" value={text} onChange={setText} />
              <button
                {...id("channel", "send")}
                onClick={() => {
                  chat.send(text);
                  setText("");
                }}
              >
                Send
              </button>
              <button {...id("channel", "close")} onClick={() => channel.close().then(() => setChannel(null))}>
                Close
              </button>
            </section>
          )}

          <section>
            <h2>Verify peer</h2>
            <button
              {...id("verify", "show")}
              onClick={() => attempt(async () => setIdentity(await qalqon.session.verifyPeer(peer())))}
            >
              Show safety number
            </button>
            {identity && (
              <>
                <p {...id("verify", "number")}>{identity.safetyNumber}</p>
                <p {...id("verify", "status")}>{identity.status}</p>
                <Field screen="verify" control="input" label="Number they read to you" value={safety} onChange={setSafety} />
                <button
                  {...id("verify", "confirm")}
                  onClick={() => attempt(async () => setIdentity(await qalqon.session.verifyPeer(peer(), safety)))}
                >
                  They match
                </button>
              </>
            )}
          </section>

          <section>
            <h2>Security</h2>
            <p {...id("security", "path")}>{info ? `Path: ${info.path}, key epoch ${info.keyEpoch}` : ""}</p>
            <button {...id("security", "rotate")} onClick={() => attempt(() => qalqon.session.rotateKeys(peer()))}>
              Rotate keys
            </button>
            <button
              {...id("security", "audit")}
              onClick={() =>
                attempt(async () => {
                  const audit = await qalqon.session.exportAudit({});
                  return `${atob(audit.events).split("\n").length - 1} audit events`;
                })
              }
            >
              Export audit
            </button>
            <button {...id("security", "logout")} onClick={() => attempt(() => qalqon.session.close())}>
              Log out
            </button>
          </section>

          <section>
            <h2>Interop</h2>
            <Field screen="interop" control="records" label="Records" value={records} onChange={setRecords} />
            <button {...id("interop", "call")} onClick={startInteropCaller}>
              Run as caller
            </button>
            <button {...id("interop", "answer")} onClick={() => setEchoMode(true)}>
              Run as answerer
            </button>
            <pre {...id("interop", "result")}>{interop}</pre>
          </section>
        </>
      )}

      <section>
        <h2>Conformance</h2>
        <textarea {...id("conformance", "input")} value={vectors} onChange={(e) => setVectors(e.target.value)} />
        <button
          {...id("conformance", "run")}
          onClick={() =>
            attempt(async () => {
              setConformance(JSON.stringify(await qalqon.client.conformanceRun(vectors)));
              return "conformance finished";
            })
          }
        >
          Run vectors
        </button>
        <pre {...id("conformance", "result")}>{conformance}</pre>
      </section>
    </main>
  );
}
