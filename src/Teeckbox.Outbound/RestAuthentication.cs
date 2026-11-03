namespace Teeckbox.Outbound;

/// <summary>
/// How a REST system is authenticated: the names of the methods and of their options, shared by the connections,
/// the REST datasources and the on-premises agent.
/// </summary>
public static class RestAuthentication
{
    public const string None = "none";
    public const string ApiKey = "apiKey";
    public const string Bearer = "bearer";
    public const string Basic = "basic";
    public const string OAuthClientCredentials = "oauthClientCredentials";
    public const string OAuthClientAssertion = "oauthClientAssertion";
    public const string OAuthPassword = "oauthPassword";

    public const string ApiKeyInHeader = "header";
    public const string ApiKeyInQuery = "query";
    public const string ClientSecretInBody = "body";
    public const string ClientSecretInBasic = "basic";

    /// <summary>The methods that obtain an access token from a token endpoint.</summary>
    public static readonly IReadOnlyList<string> OAuthMethods = [OAuthClientCredentials, OAuthClientAssertion, OAuthPassword];
}
