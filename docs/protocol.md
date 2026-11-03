# Protocol between Teeckbox and the agent

What travels between the Teeckbox server and an agent instance, and why. The code is in
[`src/Teeckbox.Outbound`](../src/Teeckbox.Outbound); every rule below has a test in
[`tests/Teeckbox.Outbound.Tests`](../tests/Teeckbox.Outbound.Tests).

## Overview

```
 your network                                   Teeckbox
┌──────────────┐   outbound HTTPS (443)    ┌─────────────────┐
│ agent        │ ────────────────────────► │ /hubs/agent     │
│ instance     │ ◄──── sealed requests ─── │ (SignalR)       │
│              │ ───── signed answers ───► │                 │
└──────┬───────┘                           └─────────────────┘
       │ only the destinations of agent.yaml
       ▼
  internal systems
```

The agent opens the connection and keeps it open. Nothing connects to the agent: no port is opened on your network.

## Keys

An instance generates two P-256 key pairs when it is enrolled and keeps the private keys on its machine:

| Key | Used to |
| --- | --- |
| signing (ECDSA) | sign the token it connects with, the answers it returns and the replacement of its keys |
| encryption (ECDH) | open the requests sealed for it |

Teeckbox only ever holds the public keys, sent at enrollment as base64 of their SubjectPublicKeyInfo.

## Enrollment

An administrator creates the agent in Teeckbox and gets a one-time code `tbe_…`: 256 random bits, shown once, valid 15 minutes,
usable once; Teeckbox stores only its SHA-256. `teeckbox-agent enroll --url … --code …` sends the code and the two public keys to
`POST /api/agents/enroll`. A code that is unknown, expired, already used, or whose agent is disabled gets the same answer.

## Connecting

The instance connects to `/hubs/agent` (SignalR over WebSocket) with `Authorization: Bearer <token>`. The token is a JWT signed
with the instance's signing key (ES256):

| Claim | Value |
| --- | --- |
| `sub` | the instance identifier |
| `aud` | the address of Teeckbox (`https://…`, the one the instance was enrolled with) |
| `iat`, `exp` | at most five minutes apart; a 30 s difference between clocks is tolerated |
| `jti` | random, accepted once |

Teeckbox accepts it when the instance and its agent exist and are enabled, the signature matches the public key it holds, the
audience is its own address, the dates are right, and the `jti` was not used before. A new token is made for every attempt. The
negotiation request of SignalR presents the same token as the connection that follows, so only the connection uses the `jti` up.
A new connection of an instance closes the previous one. Disabling an agent or an instance closes its connection at once.

## A call

Teeckbox invokes the client method `Execute(callId, envelope)` of the instance and waits for a `SignedEnvelope`.

**Request.** The request (the settings and secrets of the connection, the address, the headers, the body, the timeout) is JSON,
sealed for the instance:

1. Teeckbox makes an ephemeral P-256 key and computes an ECDH secret with the instance's public encryption key.
2. The AES-256-GCM key is `HKDF-SHA256(secret, info = "teeckbox-agent-envelope-v1" ‖ ephemeral public key ‖ recipient public key)`.
3. The nonce is 12 random bytes. The authenticated data is `callId | instanceId | "request"`, so an envelope cannot be replayed for
   another call, another instance or the other direction.

A proxy that inspects TLS on your side sees the envelope, not the credentials.

**Answer.** The agent makes the call, and seals the raw answer the same way for the ephemeral key of the request (authenticated
data `callId | instanceId | "response"`). It signs the envelope with its signing key (ES256 over the authenticated data and the
envelope), so Teeckbox knows the answer comes from that instance and was sealed for that call. An answer with a bad signature, a
bad seal or another call identifier is refused, and Teeckbox reports "the answer of the agent could not be verified" without
repeating it.

## Replacing keys

An instance sends `RotateKeys` over its open connection with its new public keys, the time, and a signature made with the signing
key it has now. Teeckbox accepts it when the keys are P-256 keys different from the current ones, the time is within five minutes,
the signature verifies, and the same request was not accepted before.

## What this does not protect

The request is sealed for the instance, but Teeckbox does not sign it: whoever can inject a message on the connection of an instance
(for example a TLS-inspecting proxy on your side) could ask it to make a call of their own choosing. The allow list of `agent.yaml`
bounds what such a call can reach, which is why it is enforced on the address actually connected to and never by Teeckbox. Teeckbox
signing its requests is a possible hardening.
