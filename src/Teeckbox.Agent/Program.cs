using System.Security.Cryptography;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Teeckbox.Agent;

public static class Program
{
    private const string Usage = """
        teeckbox-agent: lets Teeckbox call the systems of your network, with no inbound port.

        Usage:
          teeckbox-agent enroll --url <address of Teeckbox> --code <enrollment code> [options]
          teeckbox-agent run [--config <agent.yaml>]
          teeckbox-agent rotate-keys [--config <agent.yaml>]
          teeckbox-agent version

        Options:
          --config <file>        the configuration (default: $TEECKBOX_AGENT_CONFIG, then the folder of the platform)
          --data-folder <folder> where the keys are kept (default: dataFolder of the configuration, then the platform's)
          --label <text>         how this instance is shown to the administrator (default: the machine name)
          --proxy <url>          an HTTP proxy to reach Teeckbox
          --force                enroll again, replacing the keys
          --grant <account>      Windows: the account that runs the service, which may read the keys (for example "NT SERVICE\TeeckboxAgent")
        """;

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            Console.WriteLine(Usage);
            return args.Length == 0 ? 2 : 0;
        }

        var options = Options.Parse(args[1..]);
        switch (args[0])
        {
            case "version":
                Console.WriteLine(Version.Current);
                return 0;
            case "enroll":
                if (options.Get("url") is not { } url || options.Get("code") is not { } code)
                {
                    Console.Error.WriteLine("enroll needs --url and --code.");
                    return 2;
                }

                return await Enrollment.RunAsync(
                    new EnrollOptions(url, code, AgentPaths.ConfigFile(options.Get("config")), options.Get("data-folder"), options.Get("label"), options.Get("proxy"), options.Has("force"), options.Get("grant")),
                    Console.Out, Console.Error);
            case "run":
                return await RunAsync(options);
            case "rotate-keys":
                return await RotateKeysAsync(options);
            default:
                Console.Error.WriteLine($"Unknown command '{args[0]}'.{Environment.NewLine}{Usage}");
                return 2;
        }
    }

    private static (AgentConfig Config, string ConfigFile, string Folder)? Load(Options options)
    {
        var configFile = AgentPaths.ConfigFile(options.Get("config"));
        try
        {
            var config = File.Exists(configFile) ? AgentConfig.Load(configFile) : AgentConfig.Empty;
            return (config, configFile, AgentPaths.DataFolder(options.Get("data-folder"), config));
        }
        catch (ConfigException problem)
        {
            Console.Error.WriteLine($"The configuration file {configFile} is not valid:{Environment.NewLine}{problem.Message}");
            return null;
        }
    }

    private static async Task<int> RunAsync(Options options)
    {
        if (Load(options) is not var (config, configFile, folder))
        {
            return 2;
        }

        AgentIdentity identity;
        try
        {
            identity = AgentIdentity.Load(folder);
        }
        catch (InvalidOperationException problem)
        {
            Console.Error.WriteLine(problem.Message);
            return 2;
        }

        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(o => o.TimestampFormat = "yyyy-MM-dd HH:mm:ss ");
        builder.Services.AddWindowsService(o => o.ServiceName = "Teeckbox Agent");
        builder.Services.AddSystemd();
        builder.Services.AddSingleton(identity);
        builder.Services.AddSingleton(sp => new ConfigurationSource(configFile, config, sp.GetRequiredService<ILoggerFactory>().CreateLogger("Configuration")));
        builder.Services.AddSingleton(sp => new CallExecutor(() => sp.GetRequiredService<ConfigurationSource>().AllowList));
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddHostedService<AgentRuntime>();

        using var host = builder.Build();
        host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Agent").LogInformation(
            "Teeckbox agent {Version}. Allow list: {Count} rule(s).", Version.Current, config.Allow.Count);
        if (config.Allow.Count == 0)
        {
            host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Agent").LogWarning("The allow list is empty, so every call will be refused: list the destinations in {File}.", configFile);
        }

        await host.RunAsync();
        return 0;
    }

    /// <summary>Replaces the keys of this instance: the new public keys are sent over the connection, signed with the current key, and kept only once Teeckbox accepts them.</summary>
    private static async Task<int> RotateKeysAsync(Options options)
    {
        if (Load(options) is not var (config, _, folder))
        {
            return 2;
        }

        AgentIdentity current;
        try
        {
            current = AgentIdentity.Load(folder);
        }
        catch (InvalidOperationException problem)
        {
            Console.Error.WriteLine(problem.Message);
            return 2;
        }

        using (current)
        using (var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        using (var encryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
        {
            var issuedAt = DateTimeOffset.UtcNow;
            var command = new RotateKeysCommand(
                AgentKeys.PublicKeyOf(signing), AgentKeys.PublicKeyOf(encryption), issuedAt.ToUnixTimeSeconds(),
                AgentKeyRotation.Sign(current.State.InstanceId, issuedAt, AgentKeys.PublicKeyOf(signing), AgentKeys.PublicKeyOf(encryption), current.Signing));

            await using var connection = AgentRuntime.Build(current, config.Proxy);
            try
            {
                await connection.StartAsync();
                await connection.InvokeAsync("RotateKeys", command);
            }
            catch (Exception error) when (error is HttpRequestException or HubException or InvalidOperationException)
            {
                Console.Error.WriteLine("Teeckbox did not accept the new keys; the agent keeps the ones it has.");
                return 1;
            }
            finally
            {
                await connection.StopAsync();
            }

            // Teeckbox accepted them: only now are they kept.
            using var next = new AgentIdentity(current.State, signing, encryption);
            next.Save(folder, options.Get("grant"));
        }

        Console.WriteLine("The keys were replaced. Restart the agent to connect with them.");
        return 0;
    }

    private sealed class Options(Dictionary<string, string?> values)
    {
        public static Options Parse(string[] args)
        {
            var values = new Dictionary<string, string?>();
            for (var i = 0; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--", StringComparison.Ordinal))
                {
                    continue;
                }

                var name = args[i][2..];
                values[name] = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : null;
            }

            return new Options(values);
        }

        public string? Get(string name) => values.GetValueOrDefault(name);

        public bool Has(string name) => values.ContainsKey(name);
    }
}
