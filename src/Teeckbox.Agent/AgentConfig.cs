using System.Net;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Teeckbox.Agent;

/// <summary>One destination the agent may call: a host name or an address or range, and optionally the ports.</summary>
/// <param name="Host">A name such as <c>erp.corp.local</c>, or <c>*.corp.local</c> for any name below it.</param>
/// <param name="Ip">An address such as <c>10.1.2.3</c> or a range such as <c>10.1.0.0/16</c>.</param>
/// <param name="Ports">The ports allowed; empty means any port.</param>
public sealed record AllowRule(string? Host, string? Ip, IReadOnlyList<int> Ports);

/// <summary>
/// What <c>agent.yaml</c> holds: the address of Teeckbox, where the agent keeps its keys, an HTTP proxy to reach Teeckbox, and the
/// destinations the agent may call. It never holds a secret: the credentials of the systems come from Teeckbox, for the time of a call.
/// </summary>
public sealed record AgentConfig(string? Teeckbox, string? DataFolder, string? Proxy, IReadOnlyList<AllowRule> Allow)
{
    public static AgentConfig Empty { get; } = new(null, null, null, []);

    /// <exception cref="ConfigException">The file cannot be read, or holds something that is not valid. Names every problem.</exception>
    public static AgentConfig Load(string path)
    {
        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new ConfigException([$"The file {path} cannot be read: {error.Message}"]);
        }

        return Parse(text);
    }

    public static AgentConfig Parse(string yaml)
    {
        Document? document;
        try
        {
            document = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build().Deserialize<Document>(yaml);
        }
        catch (YamlDotNet.Core.YamlException error)
        {
            throw new ConfigException([$"The file is not valid YAML: {error.Message}"]);
        }

        document ??= new Document();
        var errors = new List<string>();
        var rules = new List<AllowRule>();
        for (var i = 0; i < (document.Allow?.Count ?? 0); i++)
        {
            var entry = document.Allow![i];
            var number = $"allow #{i + 1}";
            var host = entry.Host?.Trim();
            var ip = entry.Ip?.Trim();
            if (string.IsNullOrEmpty(host) == string.IsNullOrEmpty(ip))
            {
                errors.Add($"{number}: give either a host or an ip.");
                continue;
            }

            if (!string.IsNullOrEmpty(host) && !AllowList.IsValidHostPattern(host))
            {
                errors.Add($"{number}: '{host}' is not a host name (use erp.example.com, or *.example.com for any name below it).");
            }

            if (!string.IsNullOrEmpty(ip) && !AllowList.TryParseNetwork(ip, out _, out _))
            {
                errors.Add($"{number}: '{ip}' is not an IP address or a range such as 10.1.0.0/16.");
            }

            var ports = entry.Ports ?? [];
            if (ports.Any(p => p is < 1 or > 65535))
            {
                errors.Add($"{number}: a port is between 1 and 65535.");
            }

            rules.Add(new AllowRule(string.IsNullOrEmpty(host) ? null : host, string.IsNullOrEmpty(ip) ? null : ip, ports));
        }

        if (document.Teeckbox is { Length: > 0 } address && !Uri.TryCreate(address, UriKind.Absolute, out _))
        {
            errors.Add("teeckbox: the address of Teeckbox is not a valid URL.");
        }

        if (document.Proxy is { Length: > 0 } proxy && !Uri.TryCreate(proxy, UriKind.Absolute, out _))
        {
            errors.Add("proxy: the address of the proxy is not a valid URL.");
        }

        return errors.Count > 0 ? throw new ConfigException(errors) : new AgentConfig(Blank(document.Teeckbox), Blank(document.DataFolder), Blank(document.Proxy), rules);
    }

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    // The shape of the file, for the YAML reader.
    private sealed class Document
    {
        public string? Teeckbox { get; set; }

        public string? DataFolder { get; set; }

        public string? Proxy { get; set; }

        public List<Entry>? Allow { get; set; }
    }

    private sealed class Entry
    {
        public string? Host { get; set; }

        public string? Ip { get; set; }

        public List<int>? Ports { get; set; }
    }
}

public sealed class ConfigException(IReadOnlyList<string> problems) : Exception(string.Join(Environment.NewLine, problems))
{
    public IReadOnlyList<string> Problems { get; } = problems;
}

/// <summary>
/// The destinations the customer lets the agent call (ADR-0098 and the README). A name is allowed by a <c>host</c> rule; an address
/// by an <c>ip</c> rule, checked on the address the agent actually connects to. Nothing else is, whatever Teeckbox asks.
/// </summary>
public sealed class AllowList
{
    private readonly List<(string Pattern, bool Wildcard, IReadOnlyList<int> Ports)> _hosts = [];
    private readonly List<(IPAddress Network, int Prefix, IReadOnlyList<int> Ports)> _networks = [];

    public AllowList(IEnumerable<AllowRule> rules)
    {
        foreach (var rule in rules)
        {
            if (rule.Host is { } host)
            {
                // A host rule that is an address is an address rule.
                if (TryParseNetwork(host, out var literal, out var literalPrefix))
                {
                    _networks.Add((literal, literalPrefix, rule.Ports));
                }
                else
                {
                    var wildcard = host.StartsWith("*.", StringComparison.Ordinal);
                    _hosts.Add(((wildcard ? host[2..] : host).TrimEnd('.').ToLowerInvariant(), wildcard, rule.Ports));
                }
            }

            if (rule.Ip is { } ip && TryParseNetwork(ip, out var network, out var prefix))
            {
                _networks.Add((network, prefix, rule.Ports));
            }
        }
    }

    public static AllowList Empty { get; } = new([]);

    public bool IsEmpty => _hosts.Count == 0 && _networks.Count == 0;

    /// <summary>Whether a rule allows this name on this port. <c>*.example.com</c> allows names below it, not <c>example.com</c> itself.</summary>
    public bool AllowsName(string host, int port)
    {
        var name = host.TrimEnd('.').ToLowerInvariant();
        return _hosts.Any(rule => PortAllowed(rule.Ports, port)
            && (rule.Wildcard ? name.Length > rule.Pattern.Length + 1 && name.EndsWith("." + rule.Pattern, StringComparison.Ordinal) : name == rule.Pattern));
    }

    /// <summary>Whether a rule allows this address on this port.</summary>
    public bool AllowsAddress(IPAddress address, int port)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return _networks.Any(rule => PortAllowed(rule.Ports, port) && Contains(rule.Network, rule.Prefix, address));
    }

    private static bool PortAllowed(IReadOnlyList<int> ports, int port) => ports.Count == 0 || ports.Contains(port);

    private static bool Contains(IPAddress network, int prefix, IPAddress address)
    {
        if (network.AddressFamily != address.AddressFamily)
        {
            return false;
        }

        var a = network.GetAddressBytes();
        var b = address.GetAddressBytes();
        var whole = prefix / 8;
        for (var i = 0; i < whole; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        var rest = prefix % 8;
        return rest == 0 || (a[whole] & (0xFF << (8 - rest))) == (b[whole] & (0xFF << (8 - rest)));
    }

    /// <summary>An address (a range of one) or <c>address/prefix</c>.</summary>
    internal static bool TryParseNetwork(string text, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;
        var parts = text.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bits = address.GetAddressBytes().Length * 8;
        if (parts.Length == 2 ? !int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > bits : (prefix = bits) < 0)
        {
            return false;
        }

        network = address;
        return true;
    }

    /// <summary>A name, or <c>*.</c> and a name: letters, digits, hyphens and dots, no empty label.</summary>
    internal static bool IsValidHostPattern(string host)
    {
        var name = host.StartsWith("*.", StringComparison.Ordinal) ? host[2..] : host;
        return TryParseNetwork(host, out _, out _)
            || (name.Length is > 0 and <= 253 && name.TrimEnd('.').Split('.').All(label =>
                label.Length is > 0 and <= 63 && label.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')));
    }
}
