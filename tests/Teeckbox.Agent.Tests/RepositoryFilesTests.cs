using YamlDotNet.RepresentationModel;

namespace Teeckbox.Agent.Tests;

/// <summary>The files that build, publish and install the agent: a typing mistake in them is found when the release is made, which is too late.</summary>
public class RepositoryFilesTests
{
    private static string Root()
    {
        for (var folder = new DirectoryInfo(AppContext.BaseDirectory); folder is not null; folder = folder.Parent)
        {
            if (Directory.Exists(Path.Combine(folder.FullName, ".github")) && File.Exists(Path.Combine(folder.FullName, "Dockerfile")))
            {
                return folder.FullName;
            }
        }

        throw new InvalidOperationException("The root of the repository was not found.");
    }

    public static TheoryData<string> Workflows()
    {
        var data = new TheoryData<string>();
        foreach (var file in Directory.GetFiles(Path.Combine(Root(), ".github", "workflows"), "*.yml"))
        {
            data.Add(Path.GetFileName(file));
        }

        return data;
    }

    private static YamlMappingNode Load(string file)
    {
        var yaml = new YamlStream();
        using var reader = File.OpenText(Path.Combine(Root(), ".github", "workflows", file));
        yaml.Load(reader);
        return (YamlMappingNode)yaml.Documents[0].RootNode;
    }

    [Theory]
    [MemberData(nameof(Workflows))]
    public void A_workflow_is_valid_yaml_with_a_trigger_and_jobs_that_have_steps_or_a_reason_to_have_none(string file)
    {
        var workflow = Load(file);

        Assert.True(workflow.Children.ContainsKey("on") || workflow.Children.ContainsKey(new YamlScalarNode("true")), $"{file} has no trigger.");
        var jobs = Assert.IsType<YamlMappingNode>(workflow.Children[new YamlScalarNode("jobs")]);
        Assert.NotEmpty(jobs.Children);
        foreach (var job in jobs.Children)
        {
            Assert.True(((YamlMappingNode)job.Value).Children.ContainsKey("steps"), $"The job {job.Key} of {file} has no steps.");
        }
    }

    [Fact]
    public void Nothing_is_published_except_by_a_tag()
    {
        foreach (var file in new[] { "release.yml", "publish-library.yml" })
        {
            var on = (YamlMappingNode)Load(file).Children[new YamlScalarNode("on")];
            var push = (YamlMappingNode)on.Children[new YamlScalarNode("push")];
            Assert.True(push.Children.ContainsKey("tags"), $"{file} does not run on a tag.");
            Assert.False(push.Children.ContainsKey("branches"), $"{file} must not run on a branch.");
        }
    }

    [Fact]
    public void The_release_makes_a_draft_and_signs_and_attests_what_it_releases()
    {
        var text = File.ReadAllText(Path.Combine(Root(), ".github", "workflows", "release.yml"));

        Assert.Contains("--draft", text);
        Assert.Contains("attest-build-provenance", text);
        Assert.Contains("cosign sign-blob", text);
        Assert.Contains("SHA256SUMS", text);
        Assert.Contains("CycloneDX", text);
        Assert.Contains("linux-x64", text);
        Assert.Contains("linux-arm64", text);
        Assert.Contains("win-x64", text);
    }

    [Fact]
    public void The_service_file_runs_the_agent_with_the_least_it_needs()
    {
        var unit = File.ReadAllText(Path.Combine(Root(), "deploy", "linux", "teeckbox-agent.service"));

        Assert.Contains("User=teeckbox-agent", unit);
        Assert.Contains("NoNewPrivileges=true", unit);
        Assert.Contains("ProtectSystem=strict", unit);
        Assert.Contains("CapabilityBoundingSet=", unit);
        Assert.Contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", unit);
        Assert.Contains("StateDirectoryMode=0700", unit);
        Assert.DoesNotContain("User=root", unit);
    }

    [Fact]
    public void The_release_offers_the_installers_and_stamps_the_linux_script_with_its_version()
    {
        var text = File.ReadAllText(Path.Combine(Root(), ".github", "workflows", "release.yml"));
        var script = File.ReadAllText(Path.Combine(Root(), "deploy", "linux", "install.sh"));
        var installer = File.ReadAllText(Path.Combine(Root(), "deploy", "windows", "installer.iss"));

        Assert.Contains("installer.iss", text);
        Assert.Contains("s/@VERSION@/$VERSION/", text);
        Assert.Contains("teeckbox-agent-install.sh", text);
        Assert.Contains("VERSION=\"@VERSION@\"", script);
        Assert.Contains("sha256sum --check", script);
        Assert.Contains("PrivilegesRequired=admin", installer);
        Assert.Contains("NT SERVICE\\{#ServiceName}", installer);
        Assert.Contains("--allow", installer);
    }

    [Fact]
    public void The_image_runs_as_a_user_that_is_not_root()
    {
        var dockerfile = File.ReadAllText(Path.Combine(Root(), "Dockerfile"));

        Assert.Contains("USER 1654:1654", dockerfile);
        Assert.Contains("chiseled", dockerfile);
        Assert.DoesNotContain("USER root", dockerfile);
    }
}
