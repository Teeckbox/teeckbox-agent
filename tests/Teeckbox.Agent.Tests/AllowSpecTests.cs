namespace Teeckbox.Agent.Tests;

public class AllowSpecTests
{
    [Fact]
    public void Hosts_addresses_ranges_and_ports_are_read_from_a_list_separated_by_commas_or_lines()
    {
        Assert.True(AllowSpec.TryParse("erp.corp.example.com:443, *.hr.corp.example.com\n10.20.0.0/16:8443;192.168.1.5", out var rules, out _));

        Assert.Equal(4, rules.Count);
        Assert.Equal(new AllowRule("erp.corp.example.com", null, [443]), rules[0], new RuleComparer());
        Assert.Equal("*.hr.corp.example.com", rules[1].Host);
        Assert.Empty(rules[1].Ports);
        Assert.Equal("10.20.0.0/16", rules[2].Ip);
        Assert.Equal([8443], rules[2].Ports);
        Assert.Equal("192.168.1.5", rules[3].Ip);
    }

    [Fact]
    public void An_IPv6_address_is_not_split_at_its_colons()
    {
        Assert.True(AllowSpec.TryParse("fd00::1", out var rules, out _));

        Assert.Equal("fd00::1", Assert.Single(rules).Ip);
    }

    [Theory]
    [InlineData("erp.corp.example.com:0")]
    [InlineData("erp.corp.example.com:70000")]
    [InlineData("erp.corp.example.com:https")]
    [InlineData("not a host!")]
    [InlineData("bad_host/path")]
    public void A_mistake_is_named_and_nothing_is_accepted(string text)
    {
        Assert.False(AllowSpec.TryParse(text, out _, out var error));
        Assert.Contains("--allow", error);
    }

    [Fact]
    public void An_empty_list_means_no_rule()
    {
        Assert.True(AllowSpec.TryParse("  ", out var rules, out _));
        Assert.Empty(rules);
        Assert.Equal("allow: []", AllowSpec.ToYaml(rules));
    }

    [Fact]
    public void The_yaml_written_is_read_back_as_the_same_rules()
    {
        Assert.True(AllowSpec.TryParse("erp.corp.example.com:443,*.hr.example.com,10.20.0.0/16:443", out var rules, out _));

        var config = AgentConfig.Parse(AllowSpec.ToYaml(rules));

        Assert.Equal(3, config.Allow.Count);
        Assert.Equal("erp.corp.example.com", config.Allow[0].Host);
        Assert.Equal([443], config.Allow[0].Ports);
        Assert.Equal("*.hr.example.com", config.Allow[1].Host);
        Assert.Equal("10.20.0.0/16", config.Allow[2].Ip);
    }

    private sealed class RuleComparer : IEqualityComparer<AllowRule>
    {
        public bool Equals(AllowRule? x, AllowRule? y) => x!.Host == y!.Host && x.Ip == y.Ip && x.Ports.SequenceEqual(y.Ports);

        public int GetHashCode(AllowRule obj) => obj.Host?.GetHashCode() ?? 0;
    }
}
