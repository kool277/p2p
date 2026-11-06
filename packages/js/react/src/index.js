// React hooks over @qalqon/web: the Client Adapter Contract for React
// (docs/CLIENT-ADAPTER.md). An adapter adds no behaviour of its own. It creates a session,
// surfaces events as state, and exposes channels and peer verification.

import { useCallback, useEffect, useRef, useState } from "react";
import { createClient } from "@qalqon/web";

/** Connects, enrols and reports events. `peerIdentityChanged` is always surfaced. */
export function useQalqonSession() {
  const client = useRef(null);
  if (client.current === null) {
    client.current = createClient();
  }
  const [session, setSession] = useState(null);
  const [state, setState] = useState("idle");
  const [error, setError] = useState(null);
  const [events, setEvents] = useState([]);
  const [requests, setRequests] = useState([]);

  const run = useCallback(async (work) => {
    setError(null);
    try {
      return await work();
    } catch (failure) {
      setError(failure.errorName ?? String(failure));
      throw failure;
    }
  }, []);

  const enroll = useCallback((config, request) => run(() => client.current.enrollDevice(config, request)), [run]);

  const connect = useCallback(
    (config, credentials) =>
      run(async () => {
        setState("connecting");
        try {
          const opened = await client.current.connect(config, credentials);
          setSession(opened);
          setState("connected");
          return opened;
        } catch (failure) {
          setState("closed");
          throw failure;
        }
      }),
    [run],
  );

  // The nextEvent loop that the contract asks every adapter to run.
  useEffect(() => {
    if (!session) {
      return undefined;
    }
    let running = true;
    (async () => {
      while (running) {
        let event;
        try {
          event = await session.nextEvent(1000);
        } catch {
          setState("closed");
          return;
        }
        if (!event || !running) {
          continue;
        }
        setEvents((all) => [...all.slice(-199), event]);
        if (event.type === "channelRequested") {
          setRequests((all) => [...all, event]);
        }
        if (event.type === "stateChanged") {
          setState(event.state);
        }
      }
    })();
    return () => {
      running = false;
    };
  }, [session]);

  const dismissRequest = useCallback((requestId) => {
    setRequests((all) => all.filter((r) => r.requestId !== requestId));
  }, []);

  return { client: client.current, session, state, error, events, requests, dismissRequest, enroll, connect };
}

/** Reads a channel's messages into state. */
export function useChannel(channel) {
  const [messages, setMessages] = useState([]);
  useEffect(() => {
    if (!channel) {
      return undefined;
    }
    let running = true;
    (async () => {
      while (running) {
        let message;
        try {
          message = await channel.receive(1000);
        } catch {
          return;
        }
        if (message && running) {
          setMessages((all) => [...all.slice(-199), new TextDecoder().decode(message)]);
        }
      }
    })();
    return () => {
      running = false;
    };
  }, [channel]);
  return { messages, send: (text) => channel.send(text) };
}
