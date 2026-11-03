# Teeckbox agent

The code that lets [Teeckbox](https://teeckbox.com) call the systems you keep on your own network, without opening a port
and without a VPN. It is published so that you can read what runs inside your network.

| Part | What it is | Status |
| --- | --- | --- |
| [`src/Teeckbox.Outbound`](src/Teeckbox.Outbound) | The library shared by the Teeckbox server and the agent: how a call to a REST system is authenticated (API key, basic, bearer, OAuth 2.0 client credentials, signed assertion, password), headers, and the rules every call follows. Published as the NuGet package `Teeckbox.Outbound`. | Available |
| [`src/Teeckbox.Agent`](src/Teeckbox.Agent) | The program installed on your network. It opens an outbound HTTPS connection to Teeckbox, executes the calls Teeckbox asks for, and only reaches the destinations you list in `agent.yaml`. | Working; not released yet |
| [`docs/protocol.md`](docs/protocol.md) | The protocol between Teeckbox and the agent, for audit. | Available |

## Security of the communication

The agent receives, for the time of a call, the credentials of your internal systems. These are the measures that protect the
communication between the agent and Teeckbox; each one can be read in the code and has a test. The protocol is described in detail in
[docs/protocol.md](docs/protocol.md).

| Measure | How |
| --- | --- |
| **No inbound port** | The agent only connects out, over HTTPS (443), to the Teeckbox address it was enrolled with, and keeps the connection open (SignalR). It opens no listening port. An HTTP proxy is supported. |
| **One-time enrollment code** | `tbe_…`, 256 random bits, shown once, valid 15 minutes, usable once; Teeckbox stores only its SHA-256. A bad, expired or used code gets the same answer. |
| **Private keys stay on the machine** | The agent generates an ECDSA P-256 signing key pair and an ECDH P-256 encryption key pair when it is enrolled. Only the public keys are sent. |
| **Signed connection token** | Every connection presents a JWT signed with the instance's key (ES256): subject = the instance, audience = the address of Teeckbox, valid 5 minutes at most, a random `jti` accepted once. A stolen token is useless once used. |
| **Requests sealed for one instance** | Credentials are sent sealed: ECDH on P-256 with a fresh ephemeral key per message, HKDF-SHA256, AES-256-GCM, with the call, the instance and the direction authenticated. A proxy that inspects TLS, or another instance, cannot read them. |
| **Requests signed by Teeckbox** | Each request is signed (ES256) with the key of the Teeckbox installation, whose public key the agent pins at enrollment. The agent refuses a request with a bad signature, for another call or instance, older than 5 minutes, or whose call identifier it has already accepted (`AgentRequests`, `CallReplayGuard`). |
| **Answers signed and sealed** | The answer is sealed for Teeckbox's ephemeral key and signed by the instance, so Teeckbox knows which instance made the call and nothing can be swapped on the way. |
| **Your allow list** | `agent.yaml` lists the host names, IP addresses or ranges and ports the agent may call; anything else is refused, whatever Teeckbox asks. IP ranges are checked on the address actually connected to, so DNS rebinding does not get through. Teeckbox cannot read or change the file. |
| **Secrets in memory only** | Credentials live in memory for the time of a call and are never written or logged. |
| **Cut off at once** | An administrator disables an agent or an instance in Teeckbox: its connection is closed immediately and it is refused when it reconnects. |
| **Content-free logs** | Only which instance made a call and its outcome; never what was sent or answered. |
| **Verifiable releases** | Each release is published with its SHA-256, a build provenance attestation, an SBOM and a signature, so that a binary can be tied to this code. |

What these measures do not cover is listed at the end of [docs/protocol.md](docs/protocol.md#what-this-does-not-protect).

## Using the agent

```bash
# 1. In Teeckbox, Connections > Agents > New agent: you get a one-time code (valid 15 minutes, shown once).
# 2. On a machine of your network, enrol this instance:
teeckbox-agent enroll --url https://teeckbox.example.com --code tbe_...

# 3. List the destinations the agent may call in agent.yaml (see below), then run it:
teeckbox-agent run
```

`enroll` makes the two key pairs, keeps the private keys in its data folder (readable by its own account only), writes a first
`agent.yaml` and prints where everything is. `run` opens the connection to Teeckbox and keeps it open, reconnecting by itself; it runs
as a service under systemd or on Windows. `rotate-keys` replaces the keys of the instance over its connection. `version` prints the
version.

| Where | Linux | Windows |
| --- | --- | --- |
| `agent.yaml` (override with `--config` or `TEECKBOX_AGENT_CONFIG`) | `/etc/teeckbox-agent/agent.yaml` | `%ProgramData%\Teeckbox\Agentgent.yaml` |
| keys and state (`dataFolder`, or `--data-folder`) | `/var/lib/teeckbox-agent` | `%ProgramData%\Teeckbox\Agent\data` |

### agent.yaml

```yaml
teeckbox: https://teeckbox.example.com      # set by enroll: the only address the agent connects to
dataFolder: /var/lib/teeckbox-agent
proxy: http://proxy.example.com:3128        # optional: to reach Teeckbox; not used for the systems the agent calls

allow:                                      # the only destinations the agent may call
  - host: erp.corp.example.com
    ports: [443]
  - host: "*.hr.corp.example.com"           # any name below hr.corp.example.com
  - ip: 10.20.0.0/16                        # an address or a range, checked on the address actually connected to
    ports: [443, 8443]
```

A rule has a `host` or an `ip`, and optional `ports` (without them, any port). With no rule, every call is refused. The list is read
again when the file changes; a file that is not valid is refused and the list in force stays. The file never holds a secret.

## Build and test

```bash
dotnet build
dotnet test
```

Requires the .NET 10 SDK.

## Licence

[Apache-2.0](LICENSE). Teeckbox itself is a proprietary product; only the agent and this library are open.

## Security

See [SECURITY.md](SECURITY.md). Please report a vulnerability privately.
