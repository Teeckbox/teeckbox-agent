using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace Teeckbox.Agent;

/// <summary>What <c>teeckbox-agent enroll</c> was given.</summary>
public sealed record EnrollOptions(string Url, string Code, string ConfigFile, string? DataFolder, string? Label, string? Proxy, bool Force);

/// <summary>
/// Enrolls this machine with the one-time code an administrator got from Teeckbox (ADR-0098): it makes its two key pairs, sends the
/// public keys with the code, and keeps the private keys in its data folder, readable by its own account only. The private keys never
/// leave the machine. From then on the agent connects only to the address it was enrolled with.
/// </summary>
public static class Enrollment
{
    public static async Task<int> RunAsync(EnrollOptions options, TextWriter output, TextWriter error, HttpMessageHandler? handler = null, CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(options.Url, UriKind.Absolute, out var url) || (url.Scheme != Uri.UriSchemeHttps && !(url.Scheme == Uri.UriSchemeHttp && url.IsLoopback)))
        {
            await error.WriteLineAsync("The address of Teeckbox must be an https:// address (http:// is accepted for this computer only).");
            return 2;
        }

        AgentConfig config;
        try
        {
            config = File.Exists(options.ConfigFile) ? AgentConfig.Load(options.ConfigFile) : AgentConfig.Empty;
        }
        catch (ConfigException problem)
        {
            await error.WriteLineAsync($"The configuration file {options.ConfigFile} is not valid:{Environment.NewLine}{problem.Message}");
            return 2;
        }

        var folder = AgentPaths.DataFolder(options.DataFolder, config);
        if (AgentIdentity.Exists(folder) && !options.Force)
        {
            await error.WriteLineAsync($"This agent is already enrolled ({folder}). Use --force to enrol it again; the old keys are replaced.");
            return 2;
        }

        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var encryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var origin = url.GetLeftPart(UriPartial.Authority);

        EnrollmentAnswer? answer;
        using (var client = NewClient(options.Proxy ?? config.Proxy, handler))
        {
            HttpResponseMessage response;
            try
            {
                response = await client.PostAsJsonAsync($"{origin}/api/agents/enroll", new
                {
                    code = options.Code.Trim(),
                    signingPublicKey = AgentKeys.PublicKeyOf(signing),
                    encryptionPublicKey = AgentKeys.PublicKeyOf(encryption),
                    label = options.Label ?? Environment.MachineName,
                    agentVersion = Version.Current,
                }, AgentJson.Options, cancellationToken);
            }
            catch (HttpRequestException)
            {
                await error.WriteLineAsync($"Teeckbox cannot be reached at {origin}. Check the address and, if you reach it through a proxy, the proxy.");
                return 1;
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                {
                    await error.WriteLineAsync(await DescribeAsync(response, cancellationToken));
                    return 1;
                }

                answer = await response.Content.ReadFromJsonAsync<EnrollmentAnswer>(AgentJson.Options, cancellationToken);
            }
        }

        if (answer is null || !AgentKeys.IsSigningPublicKey(answer.ServerSigningPublicKey) || answer.InstanceId == Guid.Empty)
        {
            await error.WriteLineAsync("Teeckbox answered, but not with what an enrollment returns. Is the address the one of Teeckbox?");
            return 1;
        }

        var state = new AgentState(origin, answer.InstanceId, answer.AgentName ?? "", answer.ServerSigningPublicKey!, DateTimeOffset.UtcNow);
        using (var saved = new AgentIdentity(state, signing, encryption))
        {
            saved.Save(folder);
        }

        WriteConfigIfMissing(options.ConfigFile, origin, folder);
        await output.WriteLineAsync($"Enrolled as an instance of the agent \"{state.AgentName}\".");
        await output.WriteLineAsync($"Keys and state: {folder}");
        await output.WriteLineAsync($"Configuration: {options.ConfigFile}  (list the destinations the agent may call in its 'allow' section, then run 'teeckbox-agent run')");
        return 0;
    }

    internal static HttpClient NewClient(string? proxy, HttpMessageHandler? handler = null)
    {
        if (handler is not null)
        {
            return new HttpClient(handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(30) };
        }

        var socketsHandler = new SocketsHttpHandler { AllowAutoRedirect = false };
        if (proxy is not null)
        {
            socketsHandler.Proxy = new WebProxy(proxy);
            socketsHandler.UseProxy = true;
        }

        return new HttpClient(socketsHandler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    private static async Task<string> DescribeAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        // The answer to a bad code never says why it is bad: expired, used or unknown.
        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            try
            {
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                if (document.RootElement.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Object)
                {
                    return "Teeckbox refused the enrollment: " + string.Join(" ", errors.EnumerateObject().Select(e => e.Value.ToString()));
                }
            }
            catch (JsonException)
            {
            }

            return "Teeckbox refused the enrollment.";
        }

        return response.StatusCode == HttpStatusCode.NotFound
            ? "Teeckbox does not offer agents at this address (is it the right address, and the Business edition?)."
            : $"Teeckbox answered {(int)response.StatusCode}.";
    }

    private static void WriteConfigIfMissing(string path, string origin, string folder)
    {
        if (File.Exists(path))
        {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, $"""
            # The configuration of the Teeckbox agent. It never holds a secret.
            teeckbox: {origin}
            dataFolder: {folder}

            # An HTTP proxy to reach Teeckbox, if your network needs one. It is not used for the systems the agent calls.
            # proxy: http://proxy.example.com:3128

            # The only destinations the agent may call, whatever Teeckbox asks. Anything else is refused.
            # A host rule allows a name ('*.' allows any name below it); an ip rule allows an address or a range, checked on
            # the address the agent actually connects to. 'ports' is optional: without it, any port.
            allow: []
            #  - host: erp.corp.example.com
            #    ports: [443]
            #  - host: "*.hr.corp.example.com"
            #  - ip: 10.20.0.0/16
            #    ports: [443, 8443]
            """);
    }

    private sealed record EnrollmentAnswer(Guid InstanceId, string? AgentName, string? ServerSigningPublicKey);
}

internal static class Version
{
    /// <summary>The version the agent announces: the one it was published as, or "dev".</summary>
    public static string Current { get; } =
        (System.Reflection.Assembly.GetEntryAssembly()?.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion ?? "dev").Split('+')[0];
}
