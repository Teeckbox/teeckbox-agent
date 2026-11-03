using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Teeckbox.Agent;

/// <summary>
/// The agent while it runs (ADR-0098): it opens an outbound connection to Teeckbox, keeps it open, and answers the calls Teeckbox sends.
/// A call is made only when it is signed by the Teeckbox the agent was enrolled with, recent, and not accepted before; its content is
/// then opened, the call made by <see cref="CallExecutor"/>, and the answer sealed back and signed. Nothing of a call is logged.
/// </summary>
public sealed class AgentRuntime(
    AgentIdentity identity,
    ConfigurationSource configuration,
    CallExecutor executor,
    ILogger<AgentRuntime> logger,
    TimeProvider time) : BackgroundService
{
    /// <summary>The name of the method Teeckbox invokes on the agent.</summary>
    public const string Execute = "Execute";

    private readonly CallReplayGuard _calls = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await using var connection = Build(identity, configuration.Current.Proxy);
        connection.On<string, SignedRequest, SignedEnvelope>(Execute, HandleAsync);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        connection.Closed += error =>
        {
            closed.TrySetResult();
            return Task.CompletedTask;
        };
        connection.Reconnecting += _ => { logger.LogWarning("The connection to Teeckbox was lost; reconnecting."); return Task.CompletedTask; };
        connection.Reconnected += _ => { logger.LogInformation("Connected to Teeckbox again."); return Task.CompletedTask; };

        // Whatever closes the connection, the agent opens it again, slowly: Teeckbox may be restarting, or the instance disabled for a while.
        // A lost connection is reopened by SignalR itself; a connection Teeckbox closes cleanly, or that cannot be reopened, comes back here.
        var attempt = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            try
            {
                await connection.StartAsync(stoppingToken);
                logger.LogInformation("Connected to Teeckbox as instance {InstanceId} of the agent \"{Agent}\".", identity.State.InstanceId, identity.State.AgentName);
                attempt = 0;
                await Task.WhenAny(closed.Task, Task.Delay(Timeout.Infinite, stoppingToken));
                if (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                logger.LogWarning("Teeckbox closed the connection.");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception error)
            {
                logger.LogWarning("Teeckbox did not accept the connection ({Error}).", Reason(error));
            }

            var wait = RetryPolicy.Delay(attempt++);
            logger.LogInformation("Trying again in {Seconds} s.", (int)wait.TotalSeconds);
            try
            {
                await Task.Delay(wait, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        await connection.StopAsync(CancellationToken.None);
    }

    /// <summary>The connection the agent opens: to the address it was enrolled with only, with a token signed afresh for each attempt.</summary>
    internal static HubConnection Build(AgentIdentity identity, string? proxy, Func<DateTimeOffset>? clock = null)
    {
        var origin = identity.State.Origin;
        return new HubConnectionBuilder()
            .WithUrl($"{origin}/hubs/agent?version={Uri.EscapeDataString(Version.Current)}", options =>
            {
                options.AccessTokenProvider = () => Task.FromResult<string?>(AgentTokens.Create(identity.State.InstanceId, origin, identity.Signing, (clock ?? (() => DateTimeOffset.UtcNow))()));
                if (proxy is not null)
                {
                    options.Proxy = new WebProxy(proxy);
                }
            })
            .WithAutomaticReconnect(new RetryPolicy())
            .Build();
    }

    internal async Task<SignedEnvelope> HandleAsync(string callId, SignedRequest request)
    {
        var started = Stopwatch.GetTimestamp();
        var now = time.GetUtcNow();
        var instanceId = identity.State.InstanceId;

        // Only what Teeckbox signed, recently, and once. Anything else is refused before it is opened.
        if (!AgentRequests.Verify(request, callId, instanceId, identity.State.ServerSigningPublicKey, now))
        {
            logger.LogWarning("A request was refused: it is not signed by Teeckbox, is for another call, or is too old.");
            throw new HubException("The request was refused.");
        }

        if (!_calls.TryAccept(callId, now))
        {
            logger.LogWarning("A request was refused: this call was already accepted.");
            throw new HubException("The request was refused.");
        }

        AgentRequest call;
        try
        {
            var plaintext = EnvelopeSealer.Open(request.Envelope, identity.Encryption, EnvelopeSealer.Binding(callId, instanceId, "request"));
            call = JsonSerializer.Deserialize<AgentRequest>(plaintext, AgentJson.Options) ?? throw new JsonException("Empty request.");
            CryptographicOperations.ZeroMemory(plaintext);
        }
        catch (Exception error) when (error is CryptographicException or JsonException)
        {
            logger.LogWarning("A request was refused: it cannot be opened.");
            throw new HubException("The request was refused.");
        }

        if (call.CallId != callId)
        {
            logger.LogWarning("A request was refused: its content is for another call.");
            throw new HubException("The request was refused.");
        }

        var response = await executor.ExecuteAsync(call, CancellationToken.None);
        logger.LogInformation("Call {CallId}: {Outcome} in {Milliseconds} ms.", callId, response.Reached ? "answered" : response.ErrorKind.ToString(), (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);

        // The answer is sealed for the key the request came with, and signed: Teeckbox knows which instance made the call.
        var binding = EnvelopeSealer.Binding(callId, instanceId, "response");
        var envelope = EnvelopeSealer.Seal(JsonSerializer.SerializeToUtf8Bytes(response, AgentJson.Options), request.Envelope.EphemeralPublicKey, binding, out var ephemeral);
        ephemeral.Dispose();
        return new SignedEnvelope(envelope, AgentSignature.Sign(envelope, binding, identity.Signing));
    }

    private static string Reason(Exception error) => error switch
    {
        HttpRequestException { StatusCode: HttpStatusCode.Unauthorized } => "refused: the agent or the instance may be disabled",
        HttpRequestException { StatusCode: HttpStatusCode.UpgradeRequired } => "refused: this agent is of another major version than Teeckbox; install the version that matches it",
        HttpRequestException { StatusCode: { } code } => $"HTTP {(int)code}",
        HttpRequestException => "Teeckbox cannot be reached",
        _ => error.GetType().Name,
    };
}

/// <summary>How long to wait before trying again: a few seconds at first, then a minute, for as long as it takes.</summary>
internal sealed class RetryPolicy : IRetryPolicy
{
    private static readonly TimeSpan[] Delays = [TimeSpan.Zero, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30)];

    public static TimeSpan Delay(int attempt) => attempt < Delays.Length ? Delays[attempt] : TimeSpan.FromSeconds(60);

    public TimeSpan? NextRetryDelay(RetryContext retryContext) => Delay((int)Math.Min(retryContext.PreviousRetryCount, int.MaxValue));
}

/// <summary>The configuration as it is now: the allow list is read again when the file changes, the rest when the agent restarts.</summary>
public sealed class ConfigurationSource : IDisposable
{
    private readonly string _path;
    private readonly ILogger? _logger;
    private readonly FileSystemWatcher? _watcher;
    private volatile AgentConfig _current;
    private volatile AllowList _allow;
    private Timer? _debounce;

    public ConfigurationSource(string path, AgentConfig initial, ILogger? logger = null)
    {
        _path = path;
        _logger = logger;
        _current = initial;
        _allow = new AllowList(initial.Allow);
        var folder = Path.GetDirectoryName(Path.GetFullPath(path));
        if (folder is not null && Directory.Exists(folder))
        {
            _watcher = new FileSystemWatcher(folder, Path.GetFileName(path)) { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size };
            _watcher.Changed += (_, _) => Schedule();
            _watcher.Created += (_, _) => Schedule();
            _watcher.Renamed += (_, _) => Schedule();
            _watcher.EnableRaisingEvents = true;
        }
    }

    public AgentConfig Current => _current;

    public AllowList AllowList => _allow;

    /// <summary>Reads the file again now. A file that is not valid is refused and the list in force stays.</summary>
    public bool Reload()
    {
        try
        {
            var config = AgentConfig.Load(_path);
            _allow = new AllowList(config.Allow);
            _current = config;
            _logger?.LogInformation("The allow list was read again: {Count} rule(s).", config.Allow.Count);
            return true;
        }
        catch (ConfigException problem)
        {
            _logger?.LogError("The configuration changed but is not valid, so the allow list in force stays: {Problems}", problem.Message);
            return false;
        }
    }

    // Editors write a file in several steps: wait a moment before reading it.
    private void Schedule() => _debounce = new Timer(_ => Reload(), null, TimeSpan.FromMilliseconds(300), Timeout.InfiniteTimeSpan);

    public void Dispose()
    {
        _watcher?.Dispose();
        _debounce?.Dispose();
    }
}
