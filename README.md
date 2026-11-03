# Teeckbox agent

The code that lets [Teeckbox](https://teeckbox.com) call the systems you keep on your own network, without opening a port
and without a VPN. It is published so that you can read what runs inside your network.

| Part | What it is | Status |
| --- | --- | --- |
| [`src/Teeckbox.Outbound`](src/Teeckbox.Outbound) | The library shared by the Teeckbox server and the agent: how a call to a REST system is authenticated (API key, basic, bearer, OAuth 2.0 client credentials, signed assertion, password), headers, and the rules every call follows. Published as the NuGet package `Teeckbox.Outbound`. | Available |
| `teeckbox-agent` | The program installed on your network. It opens an outbound HTTPS connection to Teeckbox, executes the calls Teeckbox asks for, and only reaches the destinations you list in `agent.yaml`. | In progress |

## What you can check here

- The agent never opens a listening port: it only connects out, to the Teeckbox address it was enrolled with.
- It keeps the credentials of your systems in memory for the time of a call, and never writes or logs them.
- It refuses every destination that is not in your allow list, whatever Teeckbox asks for.

Each release of the agent is published with its SHA-256, a build provenance attestation, a software bill of materials and a
signature, so that you can verify that a binary was built from this code.

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
