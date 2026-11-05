# @qalqon/react

React hooks over `@qalqon/web`: the Client Adapter Contract for React (`docs/CLIENT-ADAPTER.md`). It has no protocol logic.

```jsx
const qalqon = useQalqonSession();   // { session, state, error, events, requests, enroll, connect, ... }
const chat = useChannel(channel);    // { messages, send }
```

`clients/web-react` is a complete example.
