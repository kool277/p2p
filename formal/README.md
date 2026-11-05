# Formal models

ProVerif models of the handshake in `docs/PROTOCOL.md`, sections 7 and 8.

```sh
docker build -t qalqon-proverif formal
formal/run.sh
```

`run.sh` compares every result with what the model expects. A query that comes back "cannot be proved" fails it.

## What these show, and what they do not

This is a **symbolic model of the message flow**. It assumes perfect primitives, so it says nothing about O'z DSt 1092, 1105 or 1106, about side channels, or about the code. No human cryptographer has reviewed it. A mistake in the model could hide a real attack.

## The models

Section 15 of the specification lists the properties to prove.

| Property | Model | Expected |
| --- | --- | --- |
| 1, 2. Secrecy and forward secrecy | `secrecy_forward.pv` | Proved |
| 3. Hybrid secrecy | `hybrid.pv` | Proved. A short model of the key agreement alone |
| 4, 7. Mutual agreement and no misbinding, including anyone registering anyone's public key under another name | `agreement_r.pv`, `agreement_i.pv` | Proved |
| 5. No impersonation from a leaked ephemeral | `ephemeral_leak.pv` | Proved |
| 6. Downgrade | `downgrade.pv` | Proved |
| 7. Key compromise impersonation | `kci.pv` | Proved |
| 8. Rekey forward secrecy | `rekey.pv` | Proved for earlier epochs. A query that later epochs fall is refuted as the specification says |
| 9. Record integrity on strict transports | Not modelled | ProVerif does not fit counters well. `core/qalqon-core/tests/records.rs` covers this with tests, which is weaker |
| 10. Server substitution, with the CA key public | `pins.pv` | Proved |

## Why to trust the results at all

The first version of this model proved everything, and that was wrong: a statement after `if ...;` had parsed as part of the then-branch, so honest runs never completed and every query was trivially true. So three models exist to fail:

| Model | What it checks | Expected |
| --- | --- | --- |
| `honest_run.pv` | The processes really complete, so the proofs are not vacuous | Reachable |
| `first_contact.pv` | With a malicious CA and no pin, an attacker reads the data. The specification says this is exposed, and if this ever passed the attacker model would be broken | Attack found |
| `negative_ik.pv` | The two-message IK flow that this design rejects really does fall to one leaked ephemeral, which is the reason given in the specification | Attack found |
