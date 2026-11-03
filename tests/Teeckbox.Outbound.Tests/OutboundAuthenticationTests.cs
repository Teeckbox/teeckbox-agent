using System.Net;
using System.Text;
using Microsoft.Extensions.Caching.Memory;

namespace Teeckbox.Outbound.Tests;

/// <summary>The authentication of a call to a REST system: what is sent, where, and what never leaks.</summary>
public class OutboundAuthenticationTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        /// <summary>The body of each request, read while the request is alive.</summary>
        public Dictionary<HttpRequestMessage, string> Bodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (request.Content is not null)
            {
                Bodies[request] = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            return answer(request);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static AuthContext Context(Dictionary<string, string> settings, Dictionary<string, string>? secrets = null, bool fresh = false) =>
        new("connection:1:1", "connection \"ERP\"", settings, secrets ?? [], fresh);

    private static OutboundAuthentication Authentication(out MemoryCache cache)
    {
        cache = new MemoryCache(new MemoryCacheOptions());
        return new OutboundAuthentication(new OAuthTokens(cache, TimeProvider.System));
    }

    private static HttpRequestMessage Get() => new(HttpMethod.Get, "https://erp.internal.example/api/people");

    [Fact]
    public async Task An_api_key_goes_in_the_header_it_names()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var context = Context(
            new() { ["authentication"] = RestAuthentication.ApiKey, ["apiKeyHeader"] = "X-Key" }, new() { ["apiKey"] = "s3cr3t" });

        await Authentication(out _).SendAsync(context, new HttpClient(handler), Get, default);

        Assert.Equal("s3cr3t", handler.Requests.Single().Headers.GetValues("X-Key").Single());
    }

    [Fact]
    public async Task An_api_key_can_go_in_the_query_and_is_encoded()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var context = Context(
            new() { ["authentication"] = RestAuthentication.ApiKey, ["apiKeyLocation"] = RestAuthentication.ApiKeyInQuery, ["apiKeyHeader"] = "api key" },
            new() { ["apiKey"] = "a&b=c" });

        await Authentication(out _).SendAsync(context, new HttpClient(handler), Get, default);

        Assert.Equal("https://erp.internal.example/api/people?api%20key=a%26b%3Dc", handler.Requests.Single().RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task Basic_and_bearer_authentication_set_the_authorization_header()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var basic = Context(new() { ["authentication"] = RestAuthentication.Basic, ["username"] = "ada" }, new() { ["password"] = "lovelace" });
        var bearer = Context(new() { ["authentication"] = RestAuthentication.Bearer }, new() { ["bearerToken"] = "tok" });

        await Authentication(out _).SendAsync(basic, new HttpClient(handler), Get, default);
        await Authentication(out _).SendAsync(bearer, new HttpClient(handler), Get, default);

        Assert.Equal("Basic " + Convert.ToBase64String("ada:lovelace"u8.ToArray()), handler.Requests[0].Headers.Authorization!.ToString());
        Assert.Equal("Bearer tok", handler.Requests[1].Headers.Authorization!.ToString());
    }

    [Fact]
    public async Task The_authentication_replaces_a_configured_header_of_the_same_name()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var context = Context(
            new() { ["authentication"] = RestAuthentication.Bearer, ["headers"] = "Authorization: Bearer old\nX-Tenant: acme" },
            new() { ["bearerToken"] = "new", ["secretHeaders"] = "X-Secret: hidden" });

        await Authentication(out _).SendAsync(context, new HttpClient(handler), Get, default);

        var request = handler.Requests.Single();
        Assert.Equal("Bearer new", request.Headers.Authorization!.ToString());
        Assert.Equal("acme", request.Headers.GetValues("X-Tenant").Single());
        Assert.Equal("hidden", request.Headers.GetValues("X-Secret").Single());
    }

    [Fact]
    public async Task A_missing_secret_is_named_but_never_shown()
    {
        var context = Context(new() { ["authentication"] = RestAuthentication.Bearer });

        var error = await Assert.ThrowsAsync<OutboundUnavailableException>(
            () => Authentication(out _).SendAsync(context, new HttpClient(new StubHandler(_ => new HttpResponseMessage())), Get, default));

        Assert.Contains("connection \"ERP\" has no bearerToken", error.Message);
    }

    private static Dictionary<string, string> OAuthSettings() => new()
    {
        ["authentication"] = RestAuthentication.OAuthClientCredentials,
        ["tokenUrl"] = "https://login.internal.example/token",
        ["clientId"] = "teeckbox",
        ["scope"] = "read",
    };

    [Fact]
    public async Task An_access_token_is_obtained_once_and_cached()
    {
        var tokenCalls = 0;
        var handler = new StubHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                tokenCalls++;
                return Json(HttpStatusCode.OK, """{ "access_token": "abc", "expires_in": 3600 }""");
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var authentication = Authentication(out _);
        var context = Context(OAuthSettings(), new() { ["clientSecret"] = "shh" });
        var client = new HttpClient(handler);

        await authentication.SendAsync(context, client, Get, default);
        await authentication.SendAsync(context, client, Get, default);

        Assert.Equal(1, tokenCalls);
        var form = handler.Bodies[handler.Requests.First(r => r.RequestUri!.AbsolutePath == "/token")];
        Assert.Contains("grant_type=client_credentials", form);
        Assert.Contains("client_id=teeckbox", form);
        Assert.Contains("client_secret=shh", form);
        Assert.Contains("scope=read", form);
        Assert.All(handler.Requests.Where(r => r.RequestUri!.AbsolutePath != "/token"), r => Assert.Equal("Bearer abc", r.Headers.Authorization!.ToString()));
    }

    [Fact]
    public async Task A_cached_token_that_is_refused_is_renewed_once_and_the_request_sent_again()
    {
        var issued = 0;
        var revoked = false;
        var handler = new StubHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                return Json(HttpStatusCode.OK, $$"""{ "access_token": "t{{++issued}}", "expires_in": 3600 }""");
            }

            return new HttpResponseMessage(revoked && request.Headers.Authorization!.Parameter == "t1" ? HttpStatusCode.Unauthorized : HttpStatusCode.OK);
        });
        var authentication = Authentication(out _);
        var context = Context(OAuthSettings(), new() { ["clientSecret"] = "shh" });
        var client = new HttpClient(handler);

        await authentication.SendAsync(context, client, Get, default); // t1 is obtained and cached.
        revoked = true; // The system revokes it before it expires.
        var response = await authentication.SendAsync(context, client, Get, default);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, issued);
    }

    [Fact]
    public async Task A_token_that_has_just_been_obtained_and_is_refused_is_not_asked_again()
    {
        var issued = 0;
        var handler = new StubHandler(request => request.RequestUri!.AbsolutePath == "/token"
            ? Json(HttpStatusCode.OK, $$"""{ "access_token": "t{{++issued}}", "expires_in": 3600 }""")
            : new HttpResponseMessage(HttpStatusCode.Unauthorized));

        var response = await Authentication(out _).SendAsync(
            Context(OAuthSettings(), new() { ["clientSecret"] = "shh" }), new HttpClient(handler), Get, default);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(1, issued);
    }

    [Fact]
    public async Task A_fresh_context_never_uses_nor_fills_the_cache()
    {
        var handler = new StubHandler(request => request.RequestUri!.AbsolutePath == "/token"
            ? Json(HttpStatusCode.OK, """{ "access_token": "abc", "expires_in": 3600 }""")
            : new HttpResponseMessage(HttpStatusCode.OK));
        var authentication = Authentication(out var cache);

        await authentication.SendAsync(Context(OAuthSettings(), new() { ["clientSecret"] = "shh" }, fresh: true), new HttpClient(handler), Get, default);

        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public async Task A_refused_token_request_repeats_the_error_code_only()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.BadRequest, """{ "error": "invalid_client", "error_description": "client_secret=shh was wrong" }"""));

        var error = await Assert.ThrowsAsync<OutboundUnavailableException>(() => Authentication(out _).SendAsync(
            Context(OAuthSettings(), new() { ["clientSecret"] = "shh" }), new HttpClient(handler), Get, default));

        Assert.Contains("answered 400 (invalid_client)", error.Message);
        Assert.DoesNotContain("shh", error.Message);
    }

    [Fact]
    public async Task A_token_answer_without_an_access_token_is_an_error()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """{ "token_type": "bearer" }"""));

        var error = await Assert.ThrowsAsync<OutboundUnavailableException>(() => Authentication(out _).SendAsync(
            Context(OAuthSettings(), new() { ["clientSecret"] = "shh" }), new HttpClient(handler), Get, default));

        Assert.Contains("without an access token", error.Message);
    }

    [Fact]
    public async Task The_private_network_permission_is_carried_to_the_token_request()
    {
        var handler = new StubHandler(request => request.RequestUri!.AbsolutePath == "/token"
            ? Json(HttpStatusCode.OK, """{ "access_token": "abc", "expires_in": 3600 }""")
            : new HttpResponseMessage(HttpStatusCode.OK));
        var context = Context(OAuthSettings(), new() { ["clientSecret"] = "shh" }) with { AllowPrivateNetwork = true };

        await Authentication(out _).SendAsync(context, new HttpClient(handler), Get, default);

        var tokenRequest = handler.Requests.First(r => r.RequestUri!.AbsolutePath == "/token");
        Assert.True(tokenRequest.Options.TryGetValue(OutboundRequestOptions.AllowInternalAddress, out var allowed) && allowed);
    }
}
