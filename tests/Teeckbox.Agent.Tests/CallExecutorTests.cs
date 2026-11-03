using System.Net;

namespace Teeckbox.Agent.Tests;

/// <summary>The calls the agent makes: where it may go, how it authenticates, what it returns, and what it never does.</summary>
public sealed class CallExecutorTests : IAsyncLifetime
{
    private TestTarget _target = null!;

    public async Task InitializeAsync() => _target = await TestTarget.StartAsync();

    public async Task DisposeAsync() => await _target.DisposeAsync();

    private sealed class FakeResolver(Func<string, IPAddress[]> answer) : IDnsResolver
    {
        public List<string> Asked { get; } = [];

        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            Asked.Add(host);
            return Task.FromResult(answer(host));
        }
    }

    private static AgentRequest Call(string url, Dictionary<string, string>? settings = null, Dictionary<string, string>? secrets = null,
        string method = "GET", string? body = null, string? headers = null, int timeout = 10, string? contentType = null) => new(
        "call-1",
        new AuthContext("connection:1:1", "connection \"ERP\"", settings ?? new() { ["authentication"] = "none" }, secrets ?? [], false),
        method, url, headers, body, contentType, timeout, 1_048_576);

    private static CallExecutor Executor(AllowList list, IDnsResolver? resolver = null) => new(() => list, resolver);

    private static AllowList Allow(params AllowRule[] rules) => new(rules);

    private AllowList Loopback => Allow(new AllowRule(null, "127.0.0.1", []));

    // ---- Where the agent may go ----

    [Fact]
    public async Task A_call_to_an_allowed_address_is_made_and_the_raw_answer_returned()
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/hello"), default);

        Assert.True(response.Reached);
        Assert.Equal(200, response.HttpStatus);
        Assert.Equal("hello", response.Body);
        Assert.Equal(AgentErrorKind.None, response.ErrorKind);
        Assert.Equal("call-1", response.CallId);
    }

    [Fact]
    public async Task With_an_empty_allow_list_nothing_is_called()
    {
        using var executor = Executor(AllowList.Empty);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/hello"), default);

        Assert.False(response.Reached);
        Assert.Equal(AgentErrorKind.DestinationRefused, response.ErrorKind);
        Assert.Equal(0, _target.Hits);
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("127.0.0.2")]
    [InlineData("192.168.0.0/16")]
    public async Task An_address_outside_the_rules_is_refused_before_anything_is_sent(string ip)
    {
        using var executor = Executor(Allow(new AllowRule(null, ip, [])));

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/hello"), default);

        Assert.Equal(AgentErrorKind.DestinationRefused, response.ErrorKind);
        Assert.Equal(0, _target.Hits);
        Assert.DoesNotContain("127.0.0.1", response.Error);
    }

    [Fact]
    public async Task A_port_outside_the_rule_is_refused()
    {
        using var executor = Executor(Allow(new AllowRule(null, "127.0.0.1", [_target.Port + 1])));

        Assert.Equal(AgentErrorKind.DestinationRefused, (await executor.ExecuteAsync(Call($"{_target.Url}/hello"), default)).ErrorKind);
        Assert.Equal(0, _target.Hits);
    }

    [Fact]
    public async Task A_name_is_allowed_by_a_host_rule_and_an_address_literal_only_by_an_ip_rule()
    {
        using var byName = Executor(Allow(new AllowRule("localhost", null, [])));
        using var wrongName = Executor(Allow(new AllowRule("erp.corp.local", null, [])));

        Assert.True((await byName.ExecuteAsync(Call($"http://localhost:{_target.Port}/hello"), default)).Reached);
        // A host rule does not allow the address itself: that is what the ip rules are for.
        Assert.Equal(AgentErrorKind.DestinationRefused, (await byName.ExecuteAsync(Call($"{_target.Url}/hello"), default)).ErrorKind);
        Assert.Equal(AgentErrorKind.DestinationRefused, (await wrongName.ExecuteAsync(Call($"http://localhost:{_target.Port}/hello"), default)).ErrorKind);
    }

    [Fact]
    public async Task A_name_that_resolves_outside_the_ip_rules_is_refused_and_one_that_resolves_inside_is_connected_to_that_address()
    {
        var elsewhere = new FakeResolver(_ => [IPAddress.Parse("203.0.113.5")]);
        using var refused = Executor(Loopback, elsewhere);
        Assert.Equal(AgentErrorKind.DestinationRefused, (await refused.ExecuteAsync(Call($"http://erp.example.test:{_target.Port}/hello"), default)).ErrorKind);
        Assert.Equal(0, _target.Hits);

        // Several answers: only the allowed one is used, and the connection goes to that address, not to the name again.
        var mixed = new FakeResolver(_ => [IPAddress.Parse("203.0.113.5"), IPAddress.Loopback]);
        using var allowed = Executor(Loopback, mixed);
        var response = await allowed.ExecuteAsync(Call($"http://erp.example.test:{_target.Port}/hello"), default);

        Assert.True(response.Reached);
        Assert.Equal("hello", response.Body);
        Assert.Single(mixed.Asked); // resolved once, for the check and for the connection
    }

    [Fact]
    public async Task A_name_whose_answer_changes_cannot_lead_somewhere_else_than_the_address_that_was_checked()
    {
        // The first answer is allowed; a second one (the rebinding) would point at the target. The connection used the first.
        var answers = new Queue<IPAddress[]>([[IPAddress.Parse("10.9.9.9")], [IPAddress.Loopback]]);
        var rebinding = new FakeResolver(_ => answers.Dequeue());
        using var executor = Executor(Allow(new AllowRule(null, "10.9.9.9", [])), rebinding);

        // 10.9.9.9 is allowed but nothing listens there: the call fails to connect, and the target is never reached.
        var response = await executor.ExecuteAsync(Call($"http://erp.example.test:{_target.Port}/hello", timeout: 2), default);

        Assert.False(response.Reached);
        Assert.Equal(0, _target.Hits);
        Assert.Single(rebinding.Asked);
    }

    [Fact]
    public async Task The_allow_list_is_read_at_each_connection_so_a_change_applies_at_once()
    {
        var current = AllowList.Empty;
        using var executor = new CallExecutor(() => current);
        Assert.Equal(AgentErrorKind.DestinationRefused, (await executor.ExecuteAsync(Call($"{_target.Url}/hello"), default)).ErrorKind);

        current = Loopback;
        // A new connection is opened for the new list: the refused one left nothing pooled.
        Assert.True((await executor.ExecuteAsync(Call($"{_target.Url}/hello"), default)).Reached);
    }

    // ---- What the agent does with the call ----

    [Fact]
    public async Task No_redirect_is_followed()
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/redirect"), default);

        Assert.True(response.Reached);
        Assert.Equal(302, response.HttpStatus);
        Assert.Null(response.Body);
    }

    [Fact]
    public async Task An_error_status_is_returned_without_what_the_system_said()
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/fail"), default);

        Assert.True(response.Reached);
        Assert.Equal(500, response.HttpStatus);
        Assert.Null(response.Body);
        Assert.DoesNotContain("hunter2", System.Text.Json.JsonSerializer.Serialize(response));
    }

    [Fact]
    public async Task An_answer_larger_than_the_limit_is_a_failure_that_says_so()
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/big"), default);

        Assert.False(response.Reached);
        Assert.Equal(AgentErrorKind.Failed, response.ErrorKind);
        Assert.Contains("larger than 1024 KB", response.Error);
        Assert.Null(response.Body);
    }

    [Fact]
    public async Task A_system_that_does_not_answer_in_time_is_a_timeout()
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/slow", timeout: 1), default);

        Assert.False(response.Reached);
        Assert.Equal(AgentErrorKind.Timeout, response.ErrorKind);
    }

    [Fact]
    public async Task A_system_that_cannot_be_reached_is_a_failure_without_its_address()
    {
        var port = _target.Port;
        await _target.DisposeAsync();
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"http://127.0.0.1:{port}/hello"), default);

        Assert.Equal(AgentErrorKind.Failed, response.ErrorKind);
        Assert.DoesNotContain("127.0.0.1", response.Error);
        _target = await TestTarget.StartAsync(); // for the disposal that follows
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("ftp://example.com/file")]
    [InlineData("")]
    public async Task Something_that_is_not_a_web_address_is_refused(string url)
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call(url), default);

        Assert.False(response.Reached);
        Assert.Equal(AgentErrorKind.Failed, response.ErrorKind);
    }

    [Fact]
    public async Task The_caller_that_stops_waiting_cancels_the_call()
    {
        using var executor = Executor(Loopback);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => executor.ExecuteAsync(Call($"{_target.Url}/slow", timeout: 60), cancel.Token));
    }

    // ---- Authentication ----

    [Fact]
    public async Task The_authentication_of_the_connection_is_applied_with_its_secrets()
    {
        using var executor = Executor(Loopback);
        var call = Call($"{_target.Url}/echo",
            new() { ["authentication"] = "bearer", ["headers"] = "X-Tenant: acme" }, new() { ["bearerToken"] = "s3cr3t" }, headers: "X-Tenant: globex");

        var response = await executor.ExecuteAsync(call, default);

        // The headers of the call come after those of the connection; the authentication is the connection's.
        Assert.Equal("Bearer s3cr3t|globex|application/json, application/xml; q=0.9", response.Body);
    }

    [Fact]
    public async Task A_body_is_sent_with_its_content_type()
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/echo-body", method: "post", body: "{\"text\":\"hi\"}"), default);

        Assert.Equal("application/json; charset=utf-8|{\"text\":\"hi\"}", response.Body);
    }

    [Fact]
    public async Task An_oauth_token_is_obtained_through_the_same_allow_list_and_kept_in_memory_until_it_expires()
    {
        using var executor = Executor(Loopback);
        var settings = new Dictionary<string, string>
        {
            ["authentication"] = "oauthClientCredentials",
            ["tokenUrl"] = $"{_target.Url}/token",
            ["clientId"] = "teeckbox",
        };
        var secrets = new Dictionary<string, string> { ["clientSecret"] = "shh" };

        var first = await executor.ExecuteAsync(Call($"{_target.Url}/echo", settings, secrets), default);
        var second = await executor.ExecuteAsync(Call($"{_target.Url}/echo", settings, secrets), default);

        Assert.StartsWith("Bearer token-from-endpoint|", first.Body);
        Assert.StartsWith("Bearer token-from-endpoint|", second.Body);
        Assert.Equal(1, _target.TokenRequests);
    }

    [Fact]
    public async Task The_token_endpoint_is_subject_to_the_allow_list_too()
    {
        using var executor = Executor(Allow(new AllowRule(null, "127.0.0.1", [_target.Port])));
        var settings = new Dictionary<string, string>
        {
            ["authentication"] = "oauthClientCredentials",
            ["tokenUrl"] = "http://203.0.113.9/token",
            ["clientId"] = "teeckbox",
        };

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/echo", settings, new() { ["clientSecret"] = "shh" }), default);

        Assert.Equal(AgentErrorKind.DestinationRefused, response.ErrorKind);
        Assert.Equal(0, _target.Hits);
    }

    [Fact]
    public async Task A_missing_secret_is_named_but_never_shown()
    {
        using var executor = Executor(Loopback);

        var response = await executor.ExecuteAsync(Call($"{_target.Url}/echo", new() { ["authentication"] = "bearer" }), default);

        Assert.Equal(AgentErrorKind.Failed, response.ErrorKind);
        Assert.Contains("bearerToken", response.Error);
    }
}
