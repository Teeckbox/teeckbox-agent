using System.Net.Http.Headers;
using System.Text;
namespace Teeckbox.Outbound;

/// <summary>
/// What the authentication of a call needs: the settings and the decrypted secrets of a datasource or of a connection
/// and the name that identifies it in messages and in the token cache.
/// </summary>
/// <param name="CacheId">Identifies the settings, version included, so a change never serves a stale token.</param>
/// <param name="Subject">How messages name it, for example <c>datasource "HR"</c>.</param>
/// <param name="Fresh">Nothing cached is used, tokens included: an administrator is testing.</param>
/// <param name="AllowPrivateNetwork">The token endpoint may be on a private network, as the connection allows.</param>
public sealed record AuthContext(
    string CacheId,
    string Subject,
    IReadOnlyDictionary<string, string> Settings,
    IReadOnlyDictionary<string, string> Secrets,
    bool Fresh,
    bool AllowPrivateNetwork = false)
{
    public string? Setting(string key) =>
        Settings.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    /// <exception cref="OutboundUnavailableException">The secret was never entered.</exception>
    public string Secret(string name) => Secrets.GetValueOrDefault(name)
        ?? throw new OutboundUnavailableException($"The {Subject} has no {name}; an administrator must enter it.");
}

/// <summary>
/// Adds the headers and the authentication of a REST system to a request: none, API key (header or query), basic,
/// bearer, or an OAuth 2.0 access token (<see cref="OAuthTokens"/>). Shared by the REST datasources and the connections.
/// </summary>
public sealed class OutboundAuthentication(OAuthTokens tokens)
{
    /// <summary>
    /// Sends the request with its headers and authentication. An access token refused with 401 may have been revoked
    /// before it expired: it is renewed once and the request sent again.
    /// </summary>
    /// <param name="create">Builds the request; called again for the second attempt, since a request is sent once.</param>
    public async Task<HttpResponseMessage> SendAsync(AuthContext context, HttpClient client, Func<HttpRequestMessage> create, CancellationToken cancellationToken)
    {
        var oauth = RestAuthentication.OAuthMethods.Contains(context.Setting("authentication") ?? RestAuthentication.None);
        for (var attempt = 0; ; attempt++)
        {
            using var request = create();
            var renewed = await AuthenticateAsync(context, client, request, renew: attempt > 0, cancellationToken);

            var response = await client.SendAsync(request, cancellationToken);
            if (response.StatusCode != System.Net.HttpStatusCode.Unauthorized || !oauth || renewed)
            {
                return response;
            }

            response.Dispose();
        }
    }

    /// <returns>Whether a new access token was obtained for this request.</returns>
    public async Task<bool> AuthenticateAsync(AuthContext context, HttpClient client, HttpRequestMessage request, bool renew, CancellationToken cancellationToken)
    {
        // The configured headers first, so the authentication replaces a header of the same name.
        foreach (var setting in new[] { context.Setting("headers"), context.Secrets.GetValueOrDefault("secretHeaders") })
        {
            foreach (var (name, value) in Headers(context, setting))
            {
                request.Headers.Remove(name);
                request.Headers.TryAddWithoutValidation(name, value);
            }
        }

        switch (context.Setting("authentication"))
        {
            case RestAuthentication.ApiKey:
                var name = context.Setting("apiKeyHeader") ?? "X-API-Key";
                if (context.Setting("apiKeyLocation") == RestAuthentication.ApiKeyInQuery)
                {
                    var uri = request.RequestUri!.AbsoluteUri;
                    request.RequestUri = new Uri($"{uri}{(uri.Contains('?') ? '&' : '?')}{Uri.EscapeDataString(name)}={Uri.EscapeDataString(context.Secret("apiKey"))}");
                }
                else
                {
                    request.Headers.Remove(name);
                    request.Headers.TryAddWithoutValidation(name, context.Secret("apiKey"));
                }

                return false;
            case RestAuthentication.Bearer:
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.Secret("bearerToken"));
                return false;
            case RestAuthentication.Basic:
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicCredentials(context.Setting("username") ?? "", context.Secret("password")));
                return false;
            case RestAuthentication.OAuthClientCredentials or RestAuthentication.OAuthClientAssertion or RestAuthentication.OAuthPassword:
                var (token, obtained) = await tokens.GetAsync(context, client, renew || context.Fresh, cancellationToken);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return obtained;
            default:
                return false;
        }
    }

    public static string BasicCredentials(string user, string password) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}"));

    private static IReadOnlyList<KeyValuePair<string, string>> Headers(AuthContext context, string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        try
        {
            return HttpHeaderLines.Parse(text);
        }
        catch (FormatException error)
        {
            throw new OutboundUnavailableException($"The headers of the {context.Subject} cannot be sent: {error.Message}", error);
        }
    }
}
