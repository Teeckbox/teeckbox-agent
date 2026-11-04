using System.Text;

namespace Teeckbox.Agent;

/// <summary>
/// The allow list as the installers pass it on the command line (<c>--allow</c>): entries separated by commas, each a host name
/// (<c>erp.corp.example.com</c>, <c>*.corp.example.com</c>) or an address or range (<c>10.20.0.0/16</c>), optionally followed by
/// <c>:port</c>. Written to <c>agent.yaml</c> as <c>allow</c> rules, with the rules of <see cref="AgentConfig"/>.
/// </summary>
public static class AllowSpec
{
    private static readonly char[] Separators = [',', ';', ' ', '\t', '\r', '\n'];

    public static bool TryParse(string? text, out IReadOnlyList<AllowRule> rules, out string error)
    {
        var list = new List<AllowRule>();
        rules = list;
        error = "";
        foreach (var entry in (text ?? "").Split(Separators, StringSplitOptions.RemoveEmptyEntries))
        {
            var target = entry;
            var ports = new List<int>();

            // A single colon followed by digits is a port; an address with several colons is IPv6, without a port.
            var colon = entry.LastIndexOf(':');
            if (colon > 0 && entry.IndexOf(':') == colon)
            {
                if (!int.TryParse(entry[(colon + 1)..], out var port) || port is < 1 or > 65535)
                {
                    error = $"--allow: the port of '{entry}' must be between 1 and 65535.";
                    return false;
                }

                target = entry[..colon];
                ports.Add(port);
            }

            if (AllowList.TryParseNetwork(target, out _, out _))
            {
                list.Add(new AllowRule(null, target, ports));
            }
            else if (AllowList.IsValidHostPattern(target))
            {
                list.Add(new AllowRule(target, null, ports));
            }
            else
            {
                error = $"--allow: '{entry}' is not a host name (erp.example.com, *.example.com) nor an address or range (10.1.0.0/16), optionally followed by :port.";
                return false;
            }
        }

        return true;
    }

    /// <summary>The <c>allow</c> section of <c>agent.yaml</c>; <c>allow: []</c> when there is no rule. Values are validated, so quoting them is enough.</summary>
    public static string ToYaml(IReadOnlyList<AllowRule> rules)
    {
        if (rules.Count == 0)
        {
            return "allow: []";
        }

        var yaml = new StringBuilder("allow:");
        foreach (var rule in rules)
        {
            yaml.Append('\n').Append("  - ").Append(rule.Host is { } host ? $"host: \"{host}\"" : $"ip: \"{rule.Ip}\"");
            if (rule.Ports.Count > 0)
            {
                yaml.Append('\n').Append("    ports: [").Append(string.Join(", ", rule.Ports)).Append(']');
            }
        }

        return yaml.ToString();
    }
}
