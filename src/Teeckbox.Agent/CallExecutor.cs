using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Caching.Memory;

namespace Teeckbox.Agent;

/// <summary>Resolves a name to addresses. Tests give their own, to play a name whose answer changes.</summary>
public interface IDnsResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

internal sealed class SystemDnsResolver : IDnsResolver
{
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Dns.GetHostAddressesAsync(host, cancellationToken);
}

/// <summary>The destination is not in the allow list. The message names no address.</summary>
public sealed class DestinationRefusedException() : Exception("The destination is not in the allow list of the agent.");

/// <summary>
/// Opens the connections of the agent, and only to what the allow list lets through. A name is allowed by a <c>host</c> rule; any
/// other name is resolved and connected to only if the address it resolved to is allowed by an <c>ip</c> rule. The connection is made
/// to the very address that was checked, not to the name again, so a name whose answer changes between the check and the connection
/// (DNS rebinding) cannot lead anywhere else. The list is read at each connection, so a change of the file applies at once.
/// </summary>
public sealed class AllowListConnector(Func<AllowList> allowList, IDnsResolver resolver)
{
    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        var port = context.DnsEndPoint.Port;
        var list = allowList();

        IPAddress[] candidates;
        var byName = false;
        if (IPAddress.TryParse(host, out var literal))
        {
            candidates = [literal];
        }
        else
        {
            byName = list.AllowsName(host, port);
            if (!byName && list.IsEmpty)
            {
                throw new DestinationRefusedException();
            }

            candidates = await resolver.ResolveAsync(host, cancellationToken);
        }

        foreach (var address in candidates.Where(a => byName || list.AllowsAddress(a, port)))
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException)
            {
                socket.Dispose();
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw candidates.Any(a => byName || list.AllowsAddress(a, port))
            ? new HttpRequestException("The system cannot be reached.")
            : new DestinationRefusedException();
    }
}

/// <summary>
/// Makes the calls Teeckbox asks for (ADR-0098), by the rules every call of Teeckbox follows: the authentication and OAuth tokens of
/// <see cref="OutboundAuthentication"/>, the timeout of the connection, no redirect, an answer read up to a limit and returned raw. The
/// destinations are the allow list's. What the system answered to a refusal or an error status is neither read nor kept, and nothing of
/// a request or an answer is logged. Credentials are in memory for the call; the only thing kept is an OAuth token, until it expires.
/// </summary>
public sealed class CallExecutor : IDisposable
{
    public const int MaxResponseBytes = 1_048_576;

    private readonly AllowListConnector _connector;
    private readonly OutboundAuthentication _authentication;
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());
    private readonly ConcurrentDictionary<string, HttpClient> _clients = new();
    private readonly HttpClient _plain;

    public CallExecutor(Func<AllowList> allowList, IDnsResolver? resolver = null, TimeProvider? time = null)
    {
        _connector = new AllowListConnector(allowList, resolver ?? new SystemDnsResolver());
        _authentication = new OutboundAuthentication(new OAuthTokens(_cache, time ?? TimeProvider.System));
        _plain = Build(null);
    }

    public async Task<AgentResponse> ExecuteAsync(AgentRequest request, CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();
        AgentResponse Failed(AgentErrorKind kind, string error, int? status = null) =>
            new(request.CallId, false, status, null, kind, error, (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);

        if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https"))
        {
            return Failed(AgentErrorKind.Failed, "The address of the call is not a web address.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(request.TimeoutSeconds, 1, 60)));
        var limit = Math.Clamp(request.MaxResponseBytes, 1, MaxResponseBytes);

        try
        {
            var context = request.Auth;
            if (!string.IsNullOrWhiteSpace(request.Headers))
            {
                // The call's headers come after the connection's, so the more specific one wins; the authentication still replaces both.
                var common = context.Setting("headers");
                context = context with
                {
                    Settings = new Dictionary<string, string>(context.Settings)
                    {
                        ["headers"] = string.IsNullOrEmpty(common) ? request.Headers : $"{common}\n{request.Headers}",
                    },
                };
            }

            var client = ClientFor(context.Secrets.GetValueOrDefault("clientCertificate"));
            using var response = await _authentication.SendAsync(context, client, () => Message(request, url), timeout.Token);

            var status = (int)response.StatusCode;
            if (status is < 200 or >= 300)
            {
                // What the system said is neither read nor kept.
                return new AgentResponse(request.CallId, true, status, null, AgentErrorKind.None, null, (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            }

            var body = await ReadAsync(response, limit, timeout.Token);
            return body is null
                ? Failed(AgentErrorKind.Failed, $"The answer is larger than {limit / 1024} KB.", status)
                : new AgentResponse(request.CallId, true, status, body, AgentErrorKind.None, null, (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        }
        catch (Exception error) when (error is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return Describe(error) switch
            {
                (var kind, var text) => Failed(kind, text),
            };
        }
    }

    /// <summary>What went wrong, in a few words that name the cause and never repeat an address, an answer or a secret.</summary>
    internal static (AgentErrorKind Kind, string Text) Describe(Exception error)
    {
        for (var inner = error; inner is not null; inner = inner.InnerException)
        {
            if (inner is DestinationRefusedException)
            {
                return (AgentErrorKind.DestinationRefused, inner.Message);
            }
        }

        return error switch
        {
            OperationCanceledException => (AgentErrorKind.Timeout, "The system did not answer in time."),
            OutboundUnavailableException unavailable => (AgentErrorKind.Failed, unavailable.Message),
            HttpRequestException => (AgentErrorKind.Failed, "The system cannot be reached."),
            _ => (AgentErrorKind.Failed, "The call failed."),
        };
    }

    private HttpClient ClientFor(string? certificatePem)
    {
        if (certificatePem is null)
        {
            return _plain;
        }

        // Keyed by the PEM's hash, so the certificate is read once and its connections are pooled.
        return _clients.GetOrAdd(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(certificatePem))), _ =>
        {
            try
            {
                return Build(ClientKeys.ReadCertificate(certificatePem));
            }
            catch (CryptographicException error)
            {
                throw new OutboundUnavailableException($"The client certificate of the connection cannot be used: {error.Message}", error);
            }
        });
    }

    private HttpClient Build(X509Certificate2? certificate)
    {
        var handler = new SocketsHttpHandler
        {
            // The agent calls systems of its own network directly: the proxy it may use to reach Teeckbox is not for them.
            UseProxy = false,
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectCallback = _connector.ConnectAsync,
        };
        if (certificate is not null)
        {
            handler.SslOptions = new SslClientAuthenticationOptions { ClientCertificates = new X509CertificateCollection { certificate } };
        }

        return new HttpClient(handler) { MaxResponseContentBufferSize = 10 * 1024 * 1024, Timeout = Timeout.InfiniteTimeSpan };
    }

    private static HttpRequestMessage Message(AgentRequest request, Uri url)
    {
        var message = new HttpRequestMessage(new HttpMethod(request.Method.ToUpperInvariant()), url);
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml", 0.9));
        if (request.Body is not null)
        {
            message.Content = new StringContent(request.Body, Encoding.UTF8, request.ContentType ?? "application/json");
        }

        return message;
    }

    /// <returns>The answer as text, or <c>null</c> when it is larger than the limit.</returns>
    private static async Task<string?> ReadAsync(HttpResponseMessage response, int limit, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > limit)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        buffer.Position = 0;
        return await new StreamReader(buffer, Encoding.UTF8, detectEncodingFromByteOrderMarks: true).ReadToEndAsync(cancellationToken);
    }

    public void Dispose()
    {
        _plain.Dispose();
        foreach (var client in _clients.Values)
        {
            client.Dispose();
        }

        _cache.Dispose();
    }
}
