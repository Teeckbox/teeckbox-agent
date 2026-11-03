using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Caching.Memory;

namespace Teeckbox.Outbound;

/// <summary>
/// Obtains the access tokens of REST datasources and connections from an OAuth 2.0 token endpoint (RFC 6749): client
/// credentials with a secret or a signed assertion (RFC 7523, <c>private_key_jwt</c>), or the legacy
/// password grant. A token is cached per datasource or connection version until shortly before it expires, whatever
/// the datasource's cache duration. The endpoint is called with the same client as the system, so it follows
/// no redirection and presents the same client certificate.
/// </summary>
public sealed class OAuthTokens(IMemoryCache cache, TimeProvider time)
{
    /// <summary>Lifetime assumed when the token endpoint gives none.</summary>
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(5);

    /// <summary>A token is renewed this long before it expires, so it never expires during a request.</summary>
    private static readonly TimeSpan Margin = TimeSpan.FromMinutes(1);

    /// <returns>The access token, and whether it was just obtained rather than read from the cache.</returns>
    public async Task<(string Token, bool Obtained)> GetAsync(AuthContext source, HttpClient client, bool renew, CancellationToken cancellationToken)
    {
        var cacheKey = $"{source.CacheId}:token";
        if (!renew && cache.TryGetValue(cacheKey, out string? cached))
        {
            return (cached!, false);
        }

        var tokenUrl = source.Setting("tokenUrl")
            ?? throw new OutboundUnavailableException($"The {source.Subject} has no token URL; an administrator must enter it.");
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl) { Content = new FormUrlEncodedContent(Form(source, tokenUrl)) };
        if (source.AllowPrivateNetwork)
        {
            request.Options.Set(OutboundRequestOptions.AllowInternalAddress, true);
        }

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (UsesBasicClientAuthentication(source))
        {
            // RFC 6749 §2.3.1: the client id and secret are form-encoded before being joined.
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", OutboundAuthentication.BasicCredentials(
                Uri.EscapeDataString(source.Setting("clientId") ?? ""),
                Uri.EscapeDataString(source.Secret("clientSecret"))));
        }

        using var response = await client.SendAsync(request, cancellationToken);
        JsonElement answer;
        try
        {
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            answer = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            answer = default;
        }

        if (!response.IsSuccessStatusCode)
        {
            // Only the error code is repeated: its description may echo what was sent.
            var code = answer.ValueKind == JsonValueKind.Object && answer.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String
                ? $" ({error.GetString()})"
                : "";
            throw new OutboundUnavailableException(
                $"The {source.Subject} could not obtain an access token: the token endpoint answered {(int)response.StatusCode}{code}.");
        }

        if (answer.ValueKind != JsonValueKind.Object || !answer.TryGetProperty("access_token", out var accessToken)
            || accessToken.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(accessToken.GetString()))
        {
            throw new OutboundUnavailableException($"The token endpoint of the {source.Subject} answered without an access token.");
        }

        var token = accessToken.GetString()!;
        var lifetime = Lifetime(answer);
        // A short-lived token is kept for half its life, a longer one until the margin before it expires.
        var kept = lifetime > 2 * Margin ? lifetime - Margin : lifetime / 2;
        if (kept > TimeSpan.Zero && !source.Fresh)
        {
            cache.Set(cacheKey, token, kept);
        }

        return (token, true);
    }

    private static bool UsesBasicClientAuthentication(AuthContext source) =>
        source.Setting("authentication") is RestAuthentication.OAuthClientCredentials or RestAuthentication.OAuthPassword
        && source.Setting("clientAuthentication") == RestAuthentication.ClientSecretInBasic;

    private Dictionary<string, string> Form(AuthContext source, string tokenUrl)
    {
        var clientId = source.Setting("clientId")
            ?? throw new OutboundUnavailableException($"The {source.Subject} has no client ID; an administrator must enter it.");
        var form = new Dictionary<string, string>();

        switch (source.Setting("authentication"))
        {
            case RestAuthentication.OAuthPassword:
                form["grant_type"] = "password";
                form["username"] = source.Setting("username") ?? "";
                form["password"] = source.Secret("password");
                break;
            case RestAuthentication.OAuthClientAssertion:
                form["grant_type"] = "client_credentials";
                form["client_id"] = clientId;
                form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                form["client_assertion"] = Assertion(source, clientId, tokenUrl);
                break;
            default:
                form["grant_type"] = "client_credentials";
                break;
        }

        if (source.Setting("authentication") is RestAuthentication.OAuthClientCredentials or RestAuthentication.OAuthPassword
            && !UsesBasicClientAuthentication(source))
        {
            form["client_id"] = clientId;
            form["client_secret"] = source.Secret("clientSecret");
        }

        if (source.Setting("scope") is { } scope)
        {
            form["scope"] = scope;
        }

        if (source.Setting("audience") is { } audience)
        {
            form["audience"] = audience;
        }

        return form;
    }

    /// <summary>
    /// A JWT signed with the private key of the datasource or connection, valid five minutes (RFC 7523 §3). The
    /// certificate's thumbprints, when it is given, let Microsoft Entra ID find the key.
    /// </summary>
    private string Assertion(AuthContext source, string clientId, string tokenUrl)
    {
        SigningKey key;
        try
        {
            key = ClientKeys.ReadSigningKey(source.Secret("clientKey"));
        }
        catch (CryptographicException error)
        {
            throw new OutboundUnavailableException($"The private key of the {source.Subject} cannot be used: {error.Message}", error);
        }

        using (key)
        {
            var header = new JsonObject { ["alg"] = key.Algorithm, ["typ"] = "JWT" };
            if (source.Setting("keyId") is { } keyId)
            {
                header["kid"] = keyId;
            }

            if (key.Certificate is { } certificate)
            {
                header["x5t"] = Base64Url(certificate.GetCertHash());
                header["x5t#S256"] = Base64Url(certificate.GetCertHash(HashAlgorithmName.SHA256));
            }

            var now = time.GetUtcNow().ToUnixTimeSeconds();
            var payload = new JsonObject
            {
                ["iss"] = clientId,
                ["sub"] = clientId,
                ["aud"] = tokenUrl,
                ["jti"] = Guid.NewGuid().ToString(),
                ["iat"] = now,
                ["nbf"] = now,
                ["exp"] = now + 300,
            };

            var signed = $"{Base64Url(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{Base64Url(Encoding.UTF8.GetBytes(payload.ToJsonString()))}";
            return $"{signed}.{Base64Url(key.Sign(Encoding.ASCII.GetBytes(signed)))}";
        }
    }

    /// <summary><c>expires_in</c>, a number of seconds, sometimes sent as a string.</summary>
    private static TimeSpan Lifetime(JsonElement answer)
    {
        if (!answer.TryGetProperty("expires_in", out var value))
        {
            return DefaultLifetime;
        }

        var seconds = value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt64(out var number) => number,
            JsonValueKind.String when long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) => number,
            _ => (long?)null,
        };
        return seconds is > 0 ? TimeSpan.FromSeconds(seconds.Value) : DefaultLifetime;
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
