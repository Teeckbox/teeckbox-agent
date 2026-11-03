using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace Teeckbox.Agent;

/// <summary>Where the agent keeps its configuration and its keys.</summary>
public static class AgentPaths
{
    public const string ConfigEnvironmentVariable = "TEECKBOX_AGENT_CONFIG";

    /// <summary><c>--config</c>, then the environment, then the place the platform expects.</summary>
    public static string ConfigFile(string? option) =>
        option ?? Environment.GetEnvironmentVariable(ConfigEnvironmentVariable) ?? Path.Combine(DefaultFolder(config: true), "agent.yaml");

    /// <summary><c>--data-folder</c>, then <c>dataFolder</c> of the configuration, then the place the platform expects.</summary>
    public static string DataFolder(string? option, AgentConfig config) =>
        option ?? config.DataFolder ?? DefaultFolder(config: false);

    private static string DefaultFolder(bool config) => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Teeckbox", "Agent", config ? "" : "data")
        : config ? "/etc/teeckbox-agent" : "/var/lib/teeckbox-agent";
}

/// <summary>What enrollment recorded. Holds no secret: the private keys are in their own files.</summary>
public sealed record AgentState(string Teeckbox, Guid InstanceId, string AgentName, string ServerSigningPublicKey, DateTimeOffset EnrolledAt)
{
    /// <summary>The address Teeckbox is reached at and the audience of the connection token: scheme, host and port.</summary>
    public string Origin => new Uri(Teeckbox).GetLeftPart(UriPartial.Authority);
}

/// <summary>The two key pairs of the instance and what enrollment recorded. Disposing it clears the keys.</summary>
public sealed class AgentIdentity(AgentState state, ECDsa signing, ECDiffieHellman encryption) : IDisposable
{
    private const string StateFile = "state.json";
    private const string SigningFile = "signing.key";
    private const string EncryptionFile = "encryption.key";

    public AgentState State { get; } = state;

    public ECDsa Signing { get; } = signing;

    public ECDiffieHellman Encryption { get; } = encryption;

    public static bool Exists(string folder) => File.Exists(Path.Combine(folder, StateFile));

    /// <exception cref="InvalidOperationException">The agent is not enrolled, or its files cannot be read.</exception>
    public static AgentIdentity Load(string folder)
    {
        try
        {
            var state = JsonSerializer.Deserialize<AgentState>(File.ReadAllText(Path.Combine(folder, StateFile)), AgentJson.Options)
                ?? throw new InvalidOperationException("The file state.json is empty.");
            var signing = ECDsa.Create();
            signing.ImportFromPem(File.ReadAllText(Path.Combine(folder, SigningFile)));
            var encryption = ECDiffieHellman.Create();
            encryption.ImportFromPem(File.ReadAllText(Path.Combine(folder, EncryptionFile)));
            return new AgentIdentity(state, signing, encryption);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or CryptographicException)
        {
            throw new InvalidOperationException($"The agent is not enrolled in {folder}, or its files cannot be read: run 'teeckbox-agent enroll' first.", error);
        }
    }

    /// <summary>Writes the keys and the state; the private keys are readable by the account of the agent only.</summary>
    public void Save(string folder)
    {
        SecureFile.CreateFolder(folder);
        SecureFile.Write(Path.Combine(folder, SigningFile), Signing.ExportPkcs8PrivateKeyPem());
        SecureFile.Write(Path.Combine(folder, EncryptionFile), Encryption.ExportPkcs8PrivateKeyPem());
        SecureFile.Write(Path.Combine(folder, StateFile), JsonSerializer.Serialize(State, new JsonSerializerOptions(AgentJson.Options) { WriteIndented = true }));
    }

    public void Dispose()
    {
        Signing.Dispose();
        Encryption.Dispose();
    }
}

/// <summary>Files only the account of the agent can read: the private keys must never be readable by anyone else.</summary>
internal static class SecureFile
{
    public static void CreateFolder(string folder)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(folder);
        }
        else
        {
            Directory.CreateDirectory(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    /// <summary>Writes the text to a new file that is already restricted, then puts it in place: the content is never readable by others.</summary>
    public static void Write(string path, string content)
    {
        var temporary = path + ".tmp";
        if (OperatingSystem.IsWindows())
        {
            using (File.Create(temporary))
            {
            }

            RestrictToCurrentUser(temporary);
            File.WriteAllText(temporary, content);
        }
        else
        {
            using var stream = new FileStream(temporary, new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            using var writer = new StreamWriter(stream);
            writer.Write(content);
        }

        File.Move(temporary, path, overwrite: true);
    }

    private static void RestrictToCurrentUser(string path)
    {
        var info = new FileInfo(path);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
        info.SetAccessControl(security);
    }
}
