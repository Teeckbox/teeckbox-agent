using System.Security.Cryptography;
using System.Text;

namespace Teeckbox.Outbound;

/// <summary>
/// A sealed request and the signature of the Teeckbox server, so the agent knows the call comes from the Teeckbox it was enrolled
/// with and not from someone who can write on its connection. The envelope hides the content; the signature authenticates it.
/// </summary>
/// <param name="IssuedAt">When the server signed it, in Unix seconds: part of what is signed, so an old request cannot be replayed.</param>
public sealed record SignedRequest(SealedEnvelope Envelope, long IssuedAt, string Signature);

/// <summary>Signs the requests Teeckbox sends and checks them on the agent's side.</summary>
public static class AgentRequests
{
    /// <summary>A request signed longer ago than this, or further in the future, is refused.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public static SignedRequest Sign(SealedEnvelope envelope, string callId, Guid instanceId, DateTimeOffset now, ECDsa serverSigningKey) =>
        new(envelope, now.ToUnixTimeSeconds(), AgentSignature.Sign(envelope, Binding(callId, instanceId, now.ToUnixTimeSeconds()), serverSigningKey));

    /// <summary>
    /// Whether the request was signed by the server whose public key the agent holds, for this call and this instance, and recently.
    /// The agent must also refuse a call identifier it has already accepted: see <see cref="CallReplayGuard"/>.
    /// </summary>
    public static bool Verify(SignedRequest request, string callId, Guid instanceId, string serverSigningPublicKey, DateTimeOffset now)
    {
        DateTimeOffset issuedAt;
        try
        {
            issuedAt = DateTimeOffset.FromUnixTimeSeconds(request.IssuedAt);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }

        return (now - issuedAt).Duration() <= Window
            && AgentSignature.Verify(request.Envelope, Binding(callId, instanceId, request.IssuedAt), request.Signature, serverSigningPublicKey);
    }

    private static byte[] Binding(string callId, Guid instanceId, long issuedAt) =>
        Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetString(EnvelopeSealer.Binding(callId, instanceId, "request"))}|{issuedAt}");
}

/// <summary>
/// Remembers the call identifiers an agent accepted for as long as a signed request stays valid, so a request that was captured
/// cannot be played again. In memory: the signature already limits a request to a few minutes.
/// </summary>
public sealed class CallReplayGuard
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, DateTimeOffset> _accepted = [];

    /// <summary>Records the call; <c>false</c> when it was already accepted.</summary>
    public bool TryAccept(string callId, DateTimeOffset now)
    {
        lock (_lock)
        {
            foreach (var old in _accepted.Where(a => a.Value <= now).Select(a => a.Key).ToList())
            {
                _accepted.Remove(old);
            }

            return _accepted.TryAdd(callId, now + AgentRequests.Window + AgentRequests.Window);
        }
    }
}
