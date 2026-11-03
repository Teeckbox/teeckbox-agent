using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Teeckbox.Agent.Tests;

/// <summary>
/// The agent as a whole, against a Teeckbox that speaks the documented protocol: enrollment, the connection, a call, and everything
/// it must refuse.
/// </summary>
public sealed class AgentEndToEndTests : IAsyncLifetime
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "teeckbox-agent-test-" + Guid.NewGuid().ToString("N"));
    private readonly CapturedLog _log = new();
    private FakeTeeckbox _teeckbox = null!;
    private TestTarget _target = null!;
    private AgentRuntime? _runtime;
    private AgentIdentity? _identity;
    private ConfigurationSource? _configuration;
    private CallExecutor? _executor;

    public async Task InitializeAsync()
    {
        _teeckbox = await FakeTeeckbox.StartAsync();
        _target = await TestTarget.StartAsync();
        Directory.CreateDirectory(_folder);
    }

    public async Task DisposeAsync()
    {
        if (_runtime is not null)
        {
            await _runtime.StopAsync(default);
            _runtime.Dispose();
        }

        _identity?.Dispose();
        _configuration?.Dispose();
        _executor?.Dispose();
        await _teeckbox.DisposeAsync();
        await _target.DisposeAsync();
        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private string ConfigFile => Path.Combine(_folder, "agent.yaml");

    private string DataFolder => Path.Combine(_folder, "data");

    /// <summary>A log that keeps what the agent logs, to check that no secret is in it.</summary>
    private sealed class CapturedLog : ILoggerProvider, ILogger
    {
        public List<string> Lines { get; } = [];

        public ILogger CreateLogger(string categoryName) => this;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (Lines)
            {
                Lines.Add($"{logLevel}: {formatter(state, exception)} {exception}");
            }
        }

        public void Dispose()
        {
        }
    }

    private Task<int> EnrollAsync(string code = FakeTeeckbox.Code, string? url = null, bool force = false, StringWriter? output = null, StringWriter? error = null) =>
        Enrollment.RunAsync(new EnrollOptions(url ?? _teeckbox.Url, code, ConfigFile, DataFolder, "erp-gateway", null, force), output ?? new StringWriter(), error ?? new StringWriter());

    /// <summary>Enrolls, allows the target, and starts the agent; returns when Teeckbox sees its connection.</summary>
    private async Task StartAgentAsync(params AllowRule[] rules)
    {
        Assert.Equal(0, await EnrollAsync());
        _identity = AgentIdentity.Load(DataFolder);
        _configuration = new ConfigurationSource(ConfigFile, new AgentConfig(null, null, null, rules));
        _executor = new CallExecutor(() => _configuration.AllowList);
        var loggers = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(_log));
        _runtime = new AgentRuntime(_identity, _configuration, _executor, loggers.CreateLogger<AgentRuntime>(), TimeProvider.System);
        await _runtime.StartAsync(default);
        await WaitAsync(() => _teeckbox.Connected);
    }

    private static async Task WaitAsync(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
        {
            await Task.Delay(50);
        }

        Assert.True(condition(), "The condition was not met in time.");
    }

    private AgentRequest Call(string path, string callId = "call-1", string secret = "s3cr3t-token") => new(
        callId,
        new AuthContext("connection:1:1", "connection \"ERP\"", new Dictionary<string, string> { ["authentication"] = "bearer" }, new Dictionary<string, string> { ["bearerToken"] = secret }, false),
        "GET", $"{_target.Url}{path}", null, null, null, 10, 1_048_576);

    private AllowRule AllowTarget => new(null, "127.0.0.1", [_target.Port]);

    // ---- Enrollment ----

    [Fact]
    public async Task Enrollment_keeps_the_keys_and_what_teeckbox_answered_and_sends_only_the_public_keys()
    {
        var output = new StringWriter();

        var code = await EnrollAsync(output: output);

        Assert.Equal(0, code);
        using var identity = AgentIdentity.Load(DataFolder);
        Assert.Equal(_teeckbox.InstanceId, identity.State.InstanceId);
        Assert.Equal("Head office", identity.State.AgentName);
        Assert.Equal(_teeckbox.Url, identity.State.Teeckbox);
        Assert.Equal(AgentKeys.PublicKeyOf(_teeckbox.ServerKey), identity.State.ServerSigningPublicKey);
        // What Teeckbox holds is the public half of what the agent kept.
        Assert.Equal(AgentKeys.PublicKeyOf(identity.Signing), _teeckbox.SigningPublicKey);
        Assert.Equal(AgentKeys.PublicKeyOf(identity.Encryption), _teeckbox.EncryptionPublicKey);
        Assert.DoesNotContain("PRIVATE", output.ToString());
        Assert.DoesNotContain("PRIVATE", File.ReadAllText(Path.Combine(DataFolder, "state.json")));
        Assert.Contains("PRIVATE KEY", File.ReadAllText(Path.Combine(DataFolder, "signing.key")));
    }

    [Fact]
    public async Task Enrollment_writes_a_configuration_with_an_empty_allow_list_and_never_overwrites_one()
    {
        await EnrollAsync();
        var config = AgentConfig.Load(ConfigFile);

        Assert.Equal(_teeckbox.Url, config.Teeckbox);
        Assert.Empty(config.Allow);

        File.WriteAllText(ConfigFile, "allow:\n  - host: erp.corp.local\n");
        await EnrollAsync(force: true);
        Assert.Equal("erp.corp.local", Assert.Single(AgentConfig.Load(ConfigFile).Allow).Host);
    }

    [Fact]
    public async Task The_private_keys_are_readable_by_their_owner_only()
    {
        await EnrollAsync();

        if (OperatingSystem.IsWindows())
        {
            // An access control list that holds one rule, for the account that runs the agent, and inherits nothing.
            foreach (var file in new[] { "signing.key", "encryption.key", "state.json" })
            {
                var security = new FileInfo(Path.Combine(DataFolder, file)).GetAccessControl();
                var rule = Assert.Single(security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)).Cast<System.Security.AccessControl.FileSystemAccessRule>());
                Assert.True(security.AreAccessRulesProtected);
                Assert.Equal(System.Security.Principal.WindowsIdentity.GetCurrent().User, rule.IdentityReference);
                Assert.Equal(System.Security.AccessControl.AccessControlType.Allow, rule.AccessControlType);
            }

            return;
        }

        foreach (var file in new[] { "signing.key", "encryption.key", "state.json" })
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(DataFolder, file)));
        }

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(DataFolder));
    }

    [Fact]
    public async Task On_windows_the_account_of_the_service_can_be_granted_the_keys_and_nobody_else()
    {
        if (!OperatingSystem.IsWindows())
        {
            var error = new StringWriter();
            var refused = await Enrollment.RunAsync(
                new EnrollOptions(_teeckbox.Url, FakeTeeckbox.Code, ConfigFile, DataFolder, null, null, false, "someone"), new StringWriter(), error);
            Assert.Equal(2, refused);
            Assert.Contains("--grant is for Windows", error.ToString());
            return;
        }

        var code = await Enrollment.RunAsync(
            new EnrollOptions(_teeckbox.Url, FakeTeeckbox.Code, ConfigFile, DataFolder, null, null, false, @"NT AUTHORITY\SYSTEM"), new StringWriter(), new StringWriter());

        Assert.Equal(0, code);
        foreach (var file in new[] { "signing.key", "encryption.key", "state.json" })
        {
            var security = new FileInfo(Path.Combine(DataFolder, file)).GetAccessControl();
            var rules = security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)).Cast<System.Security.AccessControl.FileSystemAccessRule>().ToList();
            Assert.Equal(2, rules.Count);
            Assert.Contains(rules, r => r.IdentityReference.Equals(System.Security.Principal.WindowsIdentity.GetCurrent().User) && r.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.FullControl));
            var granted = Assert.Single(rules, r => r.IdentityReference.Value == "S-1-5-18");
            Assert.False(granted.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.Write)); // it reads, it does not write
        }
    }

    [Fact]
    public void The_data_folder_comes_from_the_option_then_the_configuration_then_the_environment()
    {
        var variable = AgentPaths.DataFolderEnvironmentVariable;
        var before = Environment.GetEnvironmentVariable(variable);
        try
        {
            Environment.SetEnvironmentVariable(variable, "/from/environment");
            var configured = new AgentConfig(null, "/from/config", null, []);

            Assert.Equal("/from/option", AgentPaths.DataFolder("/from/option", configured));
            Assert.Equal("/from/config", AgentPaths.DataFolder(null, configured));
            Assert.Equal("/from/environment", AgentPaths.DataFolder(null, AgentConfig.Empty));
            Environment.SetEnvironmentVariable(variable, null);
            Assert.NotEqual("/from/environment", AgentPaths.DataFolder(null, AgentConfig.Empty));
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, before);
        }
    }

    [Fact]
    public async Task A_bad_code_is_refused_with_its_message_and_leaves_no_key_behind()
    {
        var error = new StringWriter();

        var code = await EnrollAsync("tbe_wrong", error: error);

        Assert.Equal(1, code);
        Assert.Contains("not valid, has expired or has already been used", error.ToString());
        Assert.False(AgentIdentity.Exists(DataFolder));
        Assert.False(File.Exists(Path.Combine(DataFolder, "signing.key")));
    }

    [Fact]
    public async Task An_agent_already_enrolled_is_not_enrolled_again_without_force()
    {
        await EnrollAsync();
        var first = AgentIdentity.Load(DataFolder);
        var error = new StringWriter();

        var code = await EnrollAsync(error: error);

        Assert.Equal(2, code);
        Assert.Contains("already enrolled", error.ToString());
        using var after = AgentIdentity.Load(DataFolder);
        Assert.Equal(AgentKeys.PublicKeyOf(first.Signing), AgentKeys.PublicKeyOf(after.Signing));
        Assert.Equal(1, _teeckbox.EnrollmentRequests);
        first.Dispose();
    }

    [Theory]
    [InlineData("http://teeckbox.example.com")]
    [InlineData("ftp://teeckbox.example.com")]
    [InlineData("teeckbox.example.com")]
    public async Task Only_an_https_address_is_accepted_but_this_computer_may_use_http(string url)
    {
        var error = new StringWriter();

        var code = await EnrollAsync(url: url, error: error);

        Assert.Equal(2, code);
        Assert.Contains("https://", error.ToString());
        Assert.Equal(0, _teeckbox.EnrollmentRequests);
    }

    [Fact]
    public async Task An_address_that_is_not_teeckbox_is_reported()
    {
        var error = new StringWriter();

        // A server that answers 201 with something else is not Teeckbox.
        await using var other = await TestTarget.StartAsync();
        var code = await EnrollAsync(url: other.Url, error: error);

        Assert.NotEqual(0, code);
        Assert.False(AgentIdentity.Exists(DataFolder));
    }

    // ---- Running ----

    [Fact]
    public async Task The_agent_connects_and_makes_a_call_teeckbox_signed_and_returns_a_signed_sealed_answer()
    {
        await StartAgentAsync(AllowTarget);

        var response = await _teeckbox.CallAsync(Call("/hello"));

        Assert.True(response.Reached, response.Error);
        Assert.Equal("hello", response.Body);
        Assert.Equal(["/hello"], _target.Paths.ToArray());
    }

    [Fact]
    public async Task The_credentials_of_the_call_reach_the_system_and_nothing_else()
    {
        await StartAgentAsync(AllowTarget);

        var response = await _teeckbox.CallAsync(Call("/echo", secret: "s3cr3t-token"));

        Assert.StartsWith("Bearer s3cr3t-token|", response.Body);
        Assert.DoesNotContain(_log.Lines, line => line.Contains("s3cr3t-token") || line.Contains("/echo") || line.Contains("127.0.0.1"));
        Assert.Contains(_log.Lines, line => line.Contains("call-1") && line.Contains("answered"));
    }

    [Fact]
    public async Task A_destination_outside_the_allow_list_is_refused_whatever_teeckbox_asks()
    {
        await StartAgentAsync(new AllowRule(null, "10.0.0.0/8", []));

        var response = await _teeckbox.CallAsync(Call("/hello"));

        Assert.False(response.Reached);
        Assert.Equal(AgentErrorKind.DestinationRefused, response.ErrorKind);
        Assert.Equal(0, _target.Hits);
    }

    [Fact]
    public async Task A_change_of_the_file_applies_to_the_next_call_and_a_file_that_is_not_valid_changes_nothing()
    {
        await StartAgentAsync(new AllowRule(null, "10.0.0.0/8", []));
        File.WriteAllText(ConfigFile, "teeckbox: " + _teeckbox.Url + "\nallow:\n  - ip: 127.0.0.1\n");
        Assert.True(_configuration!.Reload());
        Assert.True((await _teeckbox.CallAsync(Call("/hello", "call-1"))).Reached);

        File.WriteAllText(ConfigFile, "allow:\n  - ip: banana\n");
        Assert.False(_configuration.Reload());

        Assert.True((await _teeckbox.CallAsync(Call("/hello", "call-2"))).Reached); // the list in force stays
    }

    [Fact]
    public async Task Calls_that_arrive_together_are_made_together_and_one_slow_system_does_not_hold_the_others()
    {
        await StartAgentAsync(AllowTarget);
        var started = DateTimeOffset.UtcNow;

        var calls = await Task.WhenAll(Enumerable.Range(1, 4).Select(i => _teeckbox.CallAsync(Call("/delay", $"call-{i}"))));

        Assert.All(calls, c => Assert.Equal("done", c.Body));
        Assert.True(DateTimeOffset.UtcNow - started < TimeSpan.FromSeconds(3), "The four calls of one second each were made one after the other.");
    }

    // ---- What the agent refuses ----

    [Fact]
    public async Task A_request_not_signed_by_the_teeckbox_it_was_enrolled_with_is_refused_and_nothing_is_called()
    {
        await StartAgentAsync(AllowTarget);
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var forged = _teeckbox.MakeRequest(Call("/hello"), signWith: attacker);

        await Assert.ThrowsAnyAsync<Exception>(() => _teeckbox.SendAsync("call-1", forged));

        Assert.Equal(0, _target.Hits);
    }

    [Fact]
    public async Task A_request_that_is_old_is_refused()
    {
        await StartAgentAsync(AllowTarget);
        var stale = _teeckbox.MakeRequest(Call("/hello"), at: DateTimeOffset.UtcNow.AddMinutes(-6));

        await Assert.ThrowsAnyAsync<Exception>(() => _teeckbox.SendAsync("call-1", stale));

        Assert.Equal(0, _target.Hits);
    }

    [Fact]
    public async Task A_request_played_again_is_refused()
    {
        await StartAgentAsync(AllowTarget);
        var request = _teeckbox.MakeRequest(Call("/hello"));
        Assert.True((await _teeckbox.SendAsync("call-1", request)).Reached);

        await Assert.ThrowsAnyAsync<Exception>(() => _teeckbox.SendAsync("call-1", request));

        Assert.Equal(1, _target.Hits);
    }

    [Fact]
    public async Task A_request_sealed_for_another_call_is_refused_even_when_validly_signed()
    {
        await StartAgentAsync(AllowTarget);
        var request = _teeckbox.MakeRequest(Call("/hello", "call-1"));

        await Assert.ThrowsAnyAsync<Exception>(() => _teeckbox.SendAsync("call-2", request));

        Assert.Equal(0, _target.Hits);
    }

    // ---- The connection ----

    [Fact]
    public async Task The_agent_connects_again_by_itself_when_the_connection_drops_with_a_new_token()
    {
        await StartAgentAsync(AllowTarget);
        var opened = _teeckbox.ConnectionsOpened;

        _teeckbox.DropConnections();
        await WaitAsync(() => _teeckbox.ConnectionsOpened > opened && _teeckbox.Connected);

        Assert.True((await _teeckbox.CallAsync(Call("/hello"))).Reached);
        Assert.Empty(_teeckbox.RefusedTokens); // every connection used a token of its own
    }

    [Fact]
    public async Task The_agent_connects_to_the_address_it_was_enrolled_with_with_a_token_for_that_address()
    {
        await StartAgentAsync(AllowTarget);

        Assert.Empty(_teeckbox.RefusedTokens);
        Assert.Equal(_teeckbox.Url, _identity!.State.Origin);
    }

    // ---- Keys ----

    [Fact]
    public async Task The_keys_are_replaced_over_the_connection_and_kept_only_once_teeckbox_accepted_them()
    {
        await StartAgentAsync(AllowTarget);
        var oldSigning = _teeckbox.SigningPublicKey;
        await _runtime!.StopAsync(default);

        var code = await Program.Main(["rotate-keys", "--config", ConfigFile, "--data-folder", DataFolder]);

        Assert.Equal(0, code);
        Assert.NotEqual(oldSigning, _teeckbox.SigningPublicKey);
        using var rotated = AgentIdentity.Load(DataFolder);
        Assert.Equal(_teeckbox.SigningPublicKey, AgentKeys.PublicKeyOf(rotated.Signing));
        Assert.Equal(_teeckbox.EncryptionPublicKey, AgentKeys.PublicKeyOf(rotated.Encryption));
        Assert.Equal(_teeckbox.InstanceId, rotated.State.InstanceId);
    }

    [Fact]
    public async Task When_teeckbox_refuses_the_new_keys_the_agent_keeps_the_ones_it_has()
    {
        await StartAgentAsync(AllowTarget);
        var before = AgentKeys.PublicKeyOf(_identity!.Signing);
        await _runtime!.StopAsync(default);
        // Teeckbox no longer knows this instance's key: the connection is refused.
        _teeckbox.DropConnections();
        var folder = Path.Combine(_folder, "other");
        await using var other = await FakeTeeckbox.StartAsync();
        File.WriteAllText(ConfigFile, "");
        _identity.Save(folder);
        var url = JsonSerializer.Deserialize<AgentState>(File.ReadAllText(Path.Combine(folder, "state.json")), AgentJson.Options)!;
        File.WriteAllText(Path.Combine(folder, "state.json"), JsonSerializer.Serialize(url with { Teeckbox = other.Url }, AgentJson.Options));

        var code = await Program.Main(["rotate-keys", "--config", ConfigFile, "--data-folder", folder]);

        Assert.Equal(1, code);
        using var kept = AgentIdentity.Load(folder);
        Assert.Equal(before, AgentKeys.PublicKeyOf(kept.Signing));
    }

    // ---- The command line ----

    [Fact]
    public async Task The_version_and_the_commands_are_known()
    {
        Assert.Equal(0, await Program.Main(["version"]));
        Assert.Equal(2, await Program.Main(["nonsense"]));
        Assert.Equal(2, await Program.Main(["enroll"]));
        Assert.Equal(2, await Program.Main(["run", "--config", ConfigFile, "--data-folder", Path.Combine(_folder, "never-enrolled")]));
    }
}
