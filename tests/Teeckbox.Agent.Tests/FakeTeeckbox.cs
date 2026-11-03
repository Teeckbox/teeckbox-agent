using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Teeckbox.Agent.Tests;

/// <summary>
/// A Teeckbox as the protocol describes it, to try the agent against: it enrolls an instance with a code, accepts a connection with a
/// signed token used once, signs and seals its requests, and checks the answers. It is what <c>docs/protocol.md</c> says, not the real
/// server: the real one has its own tests, and both are tested against the same shared library.
/// </summary>
internal sealed class FakeTeeckbox : IAsyncDisposable
{
    public const string Code = "tbe_test-enrollment-code";

    private WebApplication _app = null!;
    private readonly HashSet<string> _usedTokens = [];
    private readonly List<HubCallerContext> _connections = [];
    private readonly object _lock = new();

    public string Url => _app.Urls.First();

    /// <summary>The key with which this Teeckbox signs its requests; the agent pins its public half at enrollment.</summary>
    public ECDsa ServerKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public Guid InstanceId { get; private set; }

    public string? SigningPublicKey { get; private set; }

    public string? EncryptionPublicKey { get; private set; }

    public int EnrollmentRequests { get; private set; }

    /// <summary>How many connections an instance has opened, replaced ones included.</summary>
    public int ConnectionsOpened { get; private set; }

    public bool Connected
    {
        get
        {
            lock (_lock)
            {
                return _connections.Count > 0;
            }
        }
    }

    public List<string> RefusedTokens { get; } = [];

    public static async Task<FakeTeeckbox> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddSignalR();
        var fake = new FakeTeeckbox();
        builder.Services.AddSingleton(fake);
        var app = builder.Build();
        fake._app = app;

        app.MapPost("/api/agents/enroll", async (HttpContext context) =>
        {
            fake.EnrollmentRequests++;
            using var body = await JsonDocument.ParseAsync(context.Request.Body);
            var root = body.RootElement;
            if (root.GetProperty("code").GetString() != Code)
            {
                return Results.Json(new { errors = new { code = "The enrollment code is not valid, has expired or has already been used." } }, statusCode: 400);
            }

            fake.SigningPublicKey = root.GetProperty("signingPublicKey").GetString();
            fake.EncryptionPublicKey = root.GetProperty("encryptionPublicKey").GetString();
            fake.InstanceId = Guid.NewGuid();
            return Results.Json(
                new { instanceId = fake.InstanceId, agentName = "Head office", serverSigningPublicKey = AgentKeys.PublicKeyOf(fake.ServerKey) },
                statusCode: 201);
        });

        // The token of the instance: checked against the public key it enrolled with; accepted once on the connection itself.
        app.Use(async (context, next) =>
        {
            if (!context.Request.Path.StartsWithSegments("/hubs/agent"))
            {
                await next();
                return;
            }

            var header = context.Request.Headers.Authorization.ToString();
            var token = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..] : context.Request.Query["access_token"].ToString();
            var check = fake.SigningPublicKey is null
                ? AgentTokenCheck.Invalid("not enrolled")
                : AgentTokens.Verify(token, fake.SigningPublicKey, fake.Url, DateTimeOffset.UtcNow);
            var negotiating = context.Request.Path.Value!.EndsWith("/negotiate", StringComparison.OrdinalIgnoreCase);
            bool used;
            lock (fake._lock)
            {
                used = check.Valid && !negotiating && !fake._usedTokens.Add(check.Jti!);
            }

            if (!check.Valid || used || AgentTokens.ReadSubject(token) != fake.InstanceId)
            {
                fake.RefusedTokens.Add(check.Error ?? (used ? "already used" : "wrong instance"));
                context.Response.StatusCode = 401;
                return;
            }

            await next();
        });
        app.MapHub<FakeAgentHub>("/hubs/agent");
        await app.StartAsync();
        return fake;
    }

    internal void Add(HubCallerContext context)
    {
        lock (_lock)
        {
            _connections.Add(context);
            ConnectionsOpened++;
        }
    }

    internal void Remove(HubCallerContext context)
    {
        lock (_lock)
        {
            _connections.Remove(context);
        }
    }

    /// <summary>Closes the connection from the server's side, as a restart or a network failure would.</summary>
    public void DropConnections()
    {
        lock (_lock)
        {
            _connections.ForEach(c => c.Abort());
        }
    }

    /// <summary>A request as the real Teeckbox makes it: sealed for the instance and signed. <paramref name="forge"/> changes it after.</summary>
    public SignedRequest MakeRequest(AgentRequest request, ECDsa? signWith = null, DateTimeOffset? at = null)
    {
        var envelope = EnvelopeSealer.Seal(
            JsonSerializer.SerializeToUtf8Bytes(request, AgentJson.Options), EncryptionPublicKey!, EnvelopeSealer.Binding(request.CallId, InstanceId, "request"), out var ephemeral);
        Ephemerals[request.CallId] = ephemeral;
        return AgentRequests.Sign(envelope, request.CallId, InstanceId, at ?? DateTimeOffset.UtcNow, signWith ?? ServerKey);
    }

    private Dictionary<string, ECDiffieHellman> Ephemerals { get; } = [];

    /// <summary>Sends a request to the connected instance and returns its answer, after checking the signature and the seal.</summary>
    public async Task<AgentResponse> CallAsync(AgentRequest request, TimeSpan? timeout = null) =>
        await SendAsync(request.CallId, MakeRequest(request), timeout);

    public async Task<AgentResponse> SendAsync(string callId, SignedRequest signed, TimeSpan? timeout = null)
    {
        HubCallerContext connection;
        lock (_lock)
        {
            connection = _connections.Last();
        }

        var hub = _app.Services.GetRequiredService<IHubContext<FakeAgentHub>>();
        using var cancel = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(20));
        var answer = await hub.Clients.Client(connection.ConnectionId).InvokeAsync<SignedEnvelope>(AgentRuntime.Execute, callId, signed, cancel.Token);

        var binding = EnvelopeSealer.Binding(callId, InstanceId, "response");
        Assert.True(AgentSignature.Verify(answer.Envelope, binding, answer.Signature, SigningPublicKey!), "The answer is not signed by the instance.");
        var plaintext = EnvelopeSealer.Open(answer.Envelope, Ephemerals[callId], binding);
        return JsonSerializer.Deserialize<AgentResponse>(plaintext, AgentJson.Options)!;
    }

    internal void AcceptRotation(RotateKeysCommand command)
    {
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(command.IssuedAt);
        if (!AgentKeyRotation.Verify(InstanceId, issuedAt, command.SigningPublicKey!, command.EncryptionPublicKey!, command.Signature!, SigningPublicKey!)
            || (DateTimeOffset.UtcNow - issuedAt).Duration() > AgentKeyRotation.Window)
        {
            throw new HubException("The new keys were refused.");
        }

        SigningPublicKey = command.SigningPublicKey;
        EncryptionPublicKey = command.EncryptionPublicKey;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        ServerKey.Dispose();
        foreach (var key in Ephemerals.Values)
        {
            key.Dispose();
        }
    }
}

internal sealed class FakeAgentHub(FakeTeeckbox teeckbox) : Hub
{
    public override Task OnConnectedAsync()
    {
        teeckbox.Add(Context);
        return base.OnConnectedAsync();
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        teeckbox.Remove(Context);
        return base.OnDisconnectedAsync(exception);
    }

    public void RotateKeys(RotateKeysCommand command) => teeckbox.AcceptRotation(command);
}
