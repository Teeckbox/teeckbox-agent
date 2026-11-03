using System.Text.Json;

namespace Teeckbox.Outbound;

/// <summary>Why a call through an agent has no answer from the system. Names the cause, never a secret.</summary>
public enum AgentErrorKind
{
    None,

    /// <summary>The agent refused the destination: it is not in its allow list.</summary>
    DestinationRefused,

    /// <summary>No instance of the agent is connected, or the one chosen is gone.</summary>
    Unavailable,

    /// <summary>The system, or the agent, did not answer in time.</summary>
    Timeout,

    /// <summary>The call could not be made or its answer could not be used.</summary>
    Failed,
}

/// <summary>
/// A call Teeckbox asks an agent to make. It carries what the shared code needs to authenticate the call (the settings and the
/// secrets of the connection), so the agent keeps nothing about the systems it calls. It is sent sealed for one instance.
/// </summary>
/// <param name="CallId">Identifies the call; the answer carries it back.</param>
/// <param name="Auth">The settings and decrypted secrets of the connection, and the key its OAuth token is cached under.</param>
/// <param name="Url">The absolute address to call.</param>
/// <param name="Headers">Extra headers, one <c>Name: value</c> per line, already rendered.</param>
/// <param name="MaxResponseBytes">The most the agent reads of the answer; a larger one is a failure.</param>
public sealed record AgentRequest(
    string CallId,
    AuthContext Auth,
    string Method,
    string Url,
    string? Headers,
    string? Body,
    string? ContentType,
    int TimeoutSeconds,
    int MaxResponseBytes);

/// <summary>
/// What the system answered, raw, or why there is no answer. Extraction of values stays on the server. It is sent sealed for the
/// server and signed by the instance.
/// </summary>
public sealed record AgentResponse(
    string CallId,
    bool Reached,
    int? HttpStatus,
    string? Body,
    AgentErrorKind ErrorKind,
    string? Error,
    long DurationMilliseconds)
{
    public static AgentResponse Failure(string callId, AgentErrorKind kind, string error, long milliseconds = 0) =>
        new(callId, false, null, null, kind, error, milliseconds);
}

/// <summary>
/// The new public keys an instance sends over its connection to replace its own, signed with the key it has now (see <see cref="AgentKeyRotation"/>).
/// </summary>
public sealed record RotateKeysCommand(string? SigningPublicKey, string? EncryptionPublicKey, long IssuedAt, string? Signature);

/// <summary>The JSON used on the wire between Teeckbox and an agent: the same on both sides.</summary>
public static class AgentJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
}
