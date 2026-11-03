# Teeckbox agent

The code that lets [Teeckbox](https://teeckbox.com) call the systems you keep on your own network, without opening a port
and without a VPN. It is published so that you can read what runs inside your network.

| Part | What it is | Status |
| --- | --- | --- |
| [`src/Teeckbox.Outbound`](src/Teeckbox.Outbound) | The library shared by the Teeckbox server and the agent: how a call to a REST system is authenticated (API key, basic, bearer, OAuth 2.0 client credentials, signed assertion, password), headers, and the rules every call follows. Published as the NuGet package `Teeckbox.Outbound` on [GitHub Packages](https://github.com/orgs/Teeckbox/packages) (feed `https://nuget.pkg.github.com/Teeckbox/index.json`; GitHub asks for a token with `read:packages` even to read it). | Available |
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

## Install

Download the file of your platform from the [releases](https://github.com/Teeckbox/teeckbox-agent/releases) and
[verify it](#verifying-a-release). It is one self-contained file: nothing else to install. Use the version of your Teeckbox (see
[Versions](#versions-and-upgrades)).

### Linux (systemd)

```bash
tar xzf teeckbox-agent-<version>-linux-x64.tar.gz && cd teeckbox-agent-<version>-linux-x64
sudo install -m 0755 teeckbox-agent /usr/local/bin/teeckbox-agent

# An account of its own, and a configuration it can read but not change
sudo useradd --system --home-dir /var/lib/teeckbox-agent --shell /usr/sbin/nologin teeckbox-agent
sudo install -d -o root -g teeckbox-agent -m 0750 /etc/teeckbox-agent
printf 'allow:
  - host: erp.corp.example.com
    ports: [443]
' | sudo tee /etc/teeckbox-agent/agent.yaml >/dev/null
sudo chgrp teeckbox-agent /etc/teeckbox-agent/agent.yaml && sudo chmod 0640 /etc/teeckbox-agent/agent.yaml

# Enrol as that account, so that the keys belong to it (the code comes from Connections > Agents in Teeckbox)
sudo install -d -o teeckbox-agent -g teeckbox-agent -m 0700 /var/lib/teeckbox-agent
sudo -u teeckbox-agent env TEECKBOX_AGENT_DATA_FOLDER=/var/lib/teeckbox-agent   teeckbox-agent enroll --url https://teeckbox.example.com --code tbe_... --config /etc/teeckbox-agent/agent.yaml

sudo cp teeckbox-agent.service /etc/systemd/system/
sudo systemctl enable --now teeckbox-agent
journalctl -u teeckbox-agent -f
```

The unit runs the agent as `teeckbox-agent` with no capability, a read-only system, no home, only IPv4, IPv6 and Unix sockets, and a
filtered set of system calls.

### Windows (service)

In an elevated PowerShell, in the folder of the downloaded files:

```powershell
.\install-service.ps1
.	eeckbox-agent.exe enroll --url https://teeckbox.example.com --code tbe_... `
  --config "$env:ProgramData\Teeckbox\Agentgent.yaml" --data-folder "$env:ProgramData\Teeckbox\Agent\data" `
  --grant "NT SERVICE\TeeckboxAgent"
notepad "$env:ProgramData\Teeckbox\Agentgent.yaml"     # the allow list
Start-Service TeeckboxAgent
```

The service runs under its own virtual account `NT SERVICE\TeeckboxAgent`, with no password; `--grant` lets it read the keys, which are
otherwise readable by the account that enrolled only. It restarts by itself after a failure.

### Container

```bash
docker volume create teeckbox-agent
docker run --rm -v teeckbox-agent:/data -v "$PWD/agent.yaml:/config/agent.yaml:ro"   ghcr.io/teeckbox/teeckbox-agent enroll --url https://teeckbox.example.com --code tbe_...
docker run -d --name teeckbox-agent --restart unless-stopped -v teeckbox-agent:/data -v "$PWD/agent.yaml:/config/agent.yaml:ro"   ghcr.io/teeckbox/teeckbox-agent
```

The image holds one file on a minimal base without a shell and runs as a user that is not root. The keys are in the volume mounted on
`/data`; the configuration is the file mounted on `/config/agent.yaml`. The image is published for `linux/amd64` and `linux/arm64`.

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

## Verifying a release

Each release is a draft that a maintainer publishes, with, for every file: its SHA-256 (`SHA256SUMS.txt`), a signature
(`<file>.sigstore.json`, made without a key of ours by the release workflow of this repository), a build provenance attestation, and
an SBOM (`teeckbox-agent-<version>.sbom.json`). Check a download before you install it:

```bash
sha256sum --check --ignore-missing SHA256SUMS.txt

cosign verify-blob --bundle teeckbox-agent-<version>-linux-x64.tar.gz.sigstore.json   --certificate-identity-regexp '^https://github.com/Teeckbox/teeckbox-agent/\.github/workflows/release\.yml@refs/tags/v'   --certificate-oidc-issuer https://token.actions.githubusercontent.com   teeckbox-agent-<version>-linux-x64.tar.gz

gh attestation verify teeckbox-agent-<version>-linux-x64.tar.gz --repo Teeckbox/teeckbox-agent

cosign verify ghcr.io/teeckbox/teeckbox-agent:<version>   --certificate-identity-regexp '^https://github.com/Teeckbox/teeckbox-agent/\.github/workflows/release\.yml@refs/tags/v'   --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The attestation and the signature say that the file was built by that workflow, from this repository, at the tag of the release: you
can read the workflow and the code it built.

## Versions and upgrades

The agent has its own version numbers, starting at 0.1.0; use the latest release. Teeckbox accepts an agent of **the
same major version** as itself, shows **Update available** next to an instance whose version is older, and refuses an agent of another
major version (the agent then says so in its log). A development build (`dev`) is always accepted.

To upgrade, replace the file (or pull the image) and restart the agent. The keys and the state are kept, and the instance does not
have to be enrolled again. A call in progress when the agent stops fails with a clear cause. To replace the keys without enrolling again,
run `teeckbox-agent rotate-keys` and restart.

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
