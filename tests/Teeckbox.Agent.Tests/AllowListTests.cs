using System.Net;

namespace Teeckbox.Agent.Tests;

/// <summary>The allow list and the file that holds it: the customer's last word on what the agent may reach.</summary>
public class AllowListTests
{
    private static AllowList List(params AllowRule[] rules) => new(rules);

    private static AllowRule Host(string host, params int[] ports) => new(host, null, ports);

    private static AllowRule Ip(string ip, params int[] ports) => new(null, ip, ports);

    [Fact]
    public void A_host_rule_allows_that_name_whatever_its_case_and_nothing_else()
    {
        var list = List(Host("erp.corp.local"));

        Assert.True(list.AllowsName("erp.corp.local", 443));
        Assert.True(list.AllowsName("ERP.Corp.Local", 443));
        Assert.True(list.AllowsName("erp.corp.local.", 443)); // a trailing dot is the same name
        Assert.False(list.AllowsName("hr.corp.local", 443));
        Assert.False(list.AllowsName("evil-erp.corp.local", 443));
        Assert.False(list.AllowsName("erp.corp.local.evil.com", 443));
        Assert.False(list.AllowsName("sub.erp.corp.local", 443));
    }

    [Fact]
    public void A_wildcard_allows_the_names_below_it_but_not_the_name_itself()
    {
        var list = List(Host("*.corp.local"));

        Assert.True(list.AllowsName("erp.corp.local", 443));
        Assert.True(list.AllowsName("a.b.corp.local", 443));
        Assert.False(list.AllowsName("corp.local", 443));
        Assert.False(list.AllowsName("xcorp.local", 443));
        Assert.False(list.AllowsName("corp.local.evil.com", 443));
    }

    [Fact]
    public void Ports_limit_a_rule_and_without_ports_any_port_is_allowed()
    {
        var list = List(Host("erp.corp.local", 443, 8443), Host("hr.corp.local"), Ip("10.0.0.5", 80));

        Assert.True(list.AllowsName("erp.corp.local", 8443));
        Assert.False(list.AllowsName("erp.corp.local", 80));
        Assert.True(list.AllowsName("hr.corp.local", 1));
        Assert.True(list.AllowsAddress(IPAddress.Parse("10.0.0.5"), 80));
        Assert.False(list.AllowsAddress(IPAddress.Parse("10.0.0.5"), 443));
    }

    [Theory]
    [InlineData("10.1.2.3", "10.1.2.3", true)]
    [InlineData("10.1.2.3", "10.1.2.4", false)]
    [InlineData("10.1.0.0/16", "10.1.255.255", true)]
    [InlineData("10.1.0.0/16", "10.2.0.1", false)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.0/25", "192.168.1.127", true)]
    [InlineData("192.168.1.0/25", "192.168.1.128", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("fd00::/8", "fd12:3456::1", true)]
    [InlineData("fd00::/8", "fe80::1", false)]
    [InlineData("10.0.0.0/8", "::ffff:10.1.1.1", true)] // an IPv4 address seen as IPv6
    [InlineData("10.0.0.0/8", "fd00::1", false)] // another family never matches
    public void An_address_rule_allows_an_address_or_a_range(string rule, string address, bool expected)
    {
        Assert.Equal(expected, List(Ip(rule)).AllowsAddress(IPAddress.Parse(address), 443));
    }

    [Fact]
    public void An_empty_list_allows_nothing()
    {
        Assert.True(AllowList.Empty.IsEmpty);
        Assert.False(AllowList.Empty.AllowsName("anything", 80));
        Assert.False(AllowList.Empty.AllowsAddress(IPAddress.Loopback, 80));
    }

    // ---- agent.yaml ----

    [Fact]
    public void The_file_is_read()
    {
        var config = AgentConfig.Parse("""
            teeckbox: https://teeckbox.example.com
            dataFolder: /var/lib/teeckbox-agent
            proxy: http://proxy.example.com:3128
            allow:
              - host: erp.corp.local
                ports: [443, 8443]
              - host: "*.hr.corp.local"
              - ip: 10.20.0.0/16
                ports: [443]
            """);

        Assert.Equal("https://teeckbox.example.com", config.Teeckbox);
        Assert.Equal("/var/lib/teeckbox-agent", config.DataFolder);
        Assert.Equal("http://proxy.example.com:3128", config.Proxy);
        Assert.Equal(3, config.Allow.Count);
        Assert.Equal([443, 8443], config.Allow[0].Ports);
        Assert.Equal("*.hr.corp.local", config.Allow[1].Host);
        Assert.Equal("10.20.0.0/16", config.Allow[2].Ip);
    }

    [Fact]
    public void An_empty_file_or_an_empty_list_is_valid_and_allows_nothing()
    {
        Assert.True(new AllowList(AgentConfig.Parse("").Allow).IsEmpty);
        Assert.True(new AllowList(AgentConfig.Parse("allow: []").Allow).IsEmpty);
    }

    [Theory]
    [InlineData("allow:\n  - ports: [443]", "either a host or an ip")]
    [InlineData("allow:\n  - host: a.example.com\n    ip: 10.0.0.1", "either a host or an ip")]
    [InlineData("allow:\n  - host: \"not a host!\"", "not a host name")]
    [InlineData("allow:\n  - host: \"*example.com\"", "not a host name")]
    [InlineData("allow:\n  - ip: 10.0.0.0/40", "not an IP address")]
    [InlineData("allow:\n  - ip: banana", "not an IP address")]
    [InlineData("allow:\n  - host: a.example.com\n    ports: [0]", "port is between 1 and 65535")]
    [InlineData("allow:\n  - host: a.example.com\n    ports: [70000]", "port is between 1 and 65535")]
    [InlineData("teeckbox: not a url", "not a valid URL")]
    [InlineData("proxy: nope", "not a valid URL")]
    [InlineData("allow: [", "not valid YAML")]
    [InlineData("alow: []", "not valid YAML")] // A mistyped key is an error, not silently ignored.
    public void A_file_that_is_not_valid_is_refused_with_the_reason(string yaml, string reason)
    {
        var error = Assert.Throws<ConfigException>(() => AgentConfig.Parse(yaml));

        Assert.Contains(reason, error.Message);
    }

    [Fact]
    public void Every_problem_is_reported_at_once()
    {
        var error = Assert.Throws<ConfigException>(() => AgentConfig.Parse("allow:\n  - ip: banana\n  - host: \"bad host\"\n  - ports: [1]"));

        Assert.Equal(3, error.Problems.Count);
    }
}
