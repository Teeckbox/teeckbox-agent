using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Teeckbox.Outbound;

/// <summary>The key pairs of an agent instance: one signs what it sends, the other opens what is sealed for it.</summary>
public static class AgentKeys
{
    /// <summary>Base64 of the SubjectPublicKeyInfo of a key: the form in which public keys are sent and stored.</summary>
    public static string PublicKeyOf(ECDsa key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    public static string PublicKeyOf(ECDiffieHellman key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    /// <summary>Whether the text is the base64 of the SubjectPublicKeyInfo of a P-256 ECDSA public key.</summary>
    public static bool IsSigningPublicKey(string? text)
    {
        try
        {
            using var key = ImportSigningKey(text);
            return true;
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    internal static ECDsa ImportSigningKey(string? text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(text.Trim()), out _);
            if (key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
            {
                throw new CryptographicException("The key is not on the P-256 curve.");
            }

            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }
}

/// <summary>What checking a token found.</summary>
/// <param name="Jti">The identifier of the token, which must be accepted once.</param>
/// <param name="Expires">When the token stops being valid.</param>
public sealed record AgentTokenCheck(bool Valid, string? Error, string? Jti, DateTimeOffset Expires)
{
    public static AgentTokenCheck Invalid(string error) => new(false, error, null, default);
}

/// <summary>
/// The token an agent instance signs to connect to Teeckbox: a JWT (ES256) whose subject is the instance, whose audience is
/// the address of Teeckbox, valid five minutes at most, with an identifier that is accepted once. Nothing replayable is
/// stored on the server: it checks the signature against the public key it holds.
/// </summary>
public static class AgentTokens
{
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(5);

    /// <summary>The difference between the clocks of the agent and of Teeckbox that is tolerated.</summary>
    public static readonly TimeSpan Skew = TimeSpan.FromSeconds(30);

    private const int MaxTokenLength = 1500;
    private const int MaxIdentifierLength = 64;
    private const string Header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

    public static string Create(Guid instanceId, string audience, ECDsa signingKey, DateTimeOffset now, TimeSpan? lifetime = null)
    {
        var life = lifetime ?? MaxLifetime;
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["sub"] = instanceId.ToString(),
            ["aud"] = audience,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = (now + life).ToUnixTimeSeconds(),
            ["jti"] = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16)),
        });
        var signingInput = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(Header))}.{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload))}";
        var signature = signingKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>The instance a token claims to be from, before anything is checked; <c>null</c> when it has no readable subject.</summary>
    public static Guid? ReadSubject(string? token)
    {
        if (!TrySplit(token, out var parts) || !TryPayload(parts[1], out var payload))
        {
            return null;
        }

        return payload.TryGetProperty("sub", out var sub) && sub.ValueKind == JsonValueKind.String && Guid.TryParse(sub.GetString(), out var id) ? id : null;
    }

    /// <summary>
    /// Checks the signature against the instance's public key, the audience, and the dates: issued no later than now (within the
    /// skew), expired not yet, and valid five minutes at most. The identifier is returned for the caller to accept once.
    /// </summary>
    public static AgentTokenCheck Verify(string? token, string signingPublicKey, string audience, DateTimeOffset now)
    {
        if (!TrySplit(token, out var parts) || !TryPayload(parts[1], out var payload))
        {
            return AgentTokenCheck.Invalid("The token is malformed.");
        }

        try
        {
            if (Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0])) != Header)
            {
                return AgentTokenCheck.Invalid("The token does not use ES256.");
            }

            using var key = AgentKeys.ImportSigningKey(signingPublicKey);
            if (!key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), Base64Url.DecodeFromChars(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                return AgentTokenCheck.Invalid("The signature does not match.");
            }
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return AgentTokenCheck.Invalid("The token is malformed.");
        }

        if (!Seconds(payload, "iat", out var issued) || !Seconds(payload, "exp", out var expires))
        {
            return AgentTokenCheck.Invalid("The token has no valid dates.");
        }

        if (issued > now + Skew)
        {
            return AgentTokenCheck.Invalid("The token is issued in the future.");
        }

        if (expires <= now - Skew)
        {
            return AgentTokenCheck.Invalid("The token has expired.");
        }

        if (expires - issued > MaxLifetime)
        {
            return AgentTokenCheck.Invalid("The token is valid for too long.");
        }

        if (!payload.TryGetProperty("aud", out var aud) || aud.ValueKind != JsonValueKind.String || !SameAddress(aud.GetString(), audience))
        {
            return AgentTokenCheck.Invalid("The token is for another address.");
        }

        if (!payload.TryGetProperty("jti", out var jti) || jti.ValueKind != JsonValueKind.String || jti.GetString() is not { Length: > 0 and <= MaxIdentifierLength } id)
        {
            return AgentTokenCheck.Invalid("The token has no identifier.");
        }

        return new AgentTokenCheck(true, null, id, expires);
    }

    private static bool SameAddress(string? a, string b) =>
        string.Equals(a?.Trim().TrimEnd('/'), b.Trim().TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

    private static bool TrySplit(string? token, out string[] parts)
    {
        parts = token is { Length: > 0 and <= MaxTokenLength } ? token.Split('.') : [];
        return parts.Length == 3 && parts.All(p => p.Length > 0);
    }

    private static bool TryPayload(string encoded, out JsonElement payload)
    {
        payload = default;
        try
        {
            using var document = JsonDocument.Parse(Base64Url.DecodeFromChars(encoded));
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            payload = document.RootElement.Clone();
            return true;
        }
        catch (Exception error) when (error is JsonException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    private static bool Seconds(JsonElement payload, string name, out DateTimeOffset value)
    {
        value = default;
        if (!payload.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var seconds)
            || seconds is < 0 or > 253402300799)
        {
            return false;
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }
}

/// <summary>The signature an instance puts on the answer it seals, so Teeckbox knows the answer comes from that instance.</summary>
public static class AgentSignature
{
    public static string Sign(SealedEnvelope envelope, ReadOnlySpan<byte> binding, ECDsa signingKey) =>
        Convert.ToBase64String(signingKey.SignData(Data(envelope, binding), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    public static bool Verify(SealedEnvelope envelope, ReadOnlySpan<byte> binding, string signature, string signingPublicKey)
    {
        try
        {
            using var key = AgentKeys.ImportSigningKey(signingPublicKey);
            return key.VerifyData(Data(envelope, binding), Convert.FromBase64String(signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    private static byte[] Data(SealedEnvelope envelope, ReadOnlySpan<byte> binding)
    {
        var body = Encoding.UTF8.GetBytes($"{envelope.Version}|{envelope.EphemeralPublicKey}|{envelope.Nonce}|{envelope.Ciphertext}");
        var data = new byte[binding.Length + 1 + body.Length];
        binding.CopyTo(data);
        body.CopyTo(data, binding.Length + 1);
        return data;
    }
}

/// <summary>
/// The new public keys an instance sends to replace its own, signed with the key it has now (ADR-0098): no administrator is
/// needed, and nobody who lacks the current private key can do it.
/// </summary>
public static class AgentKeyRotation
{
    /// <summary>A rotation request older than this, or from further in the future, is refused.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public static string Sign(Guid instanceId, DateTimeOffset issuedAt, string newSigningPublicKey, string newEncryptionPublicKey, ECDsa currentKey) =>
        Convert.ToBase64String(currentKey.SignData(Data(instanceId, issuedAt, newSigningPublicKey, newEncryptionPublicKey), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    public static bool Verify(Guid instanceId, DateTimeOffset issuedAt, string newSigningPublicKey, string newEncryptionPublicKey, string signature, string currentSigningPublicKey)
    {
        try
        {
            using var key = AgentKeys.ImportSigningKey(currentSigningPublicKey);
            return key.VerifyData(Data(instanceId, issuedAt, newSigningPublicKey, newEncryptionPublicKey), Convert.FromBase64String(signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    private static byte[] Data(Guid instanceId, DateTimeOffset issuedAt, string newSigning, string newEncryption) =>
        Encoding.UTF8.GetBytes($"teeckbox-agent-rotate-v1|{instanceId:N}|{issuedAt.ToUnixTimeSeconds()}|{newSigning}|{newEncryption}");
}
