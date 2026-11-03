using System.Security.Cryptography;
using System.Text;

namespace Teeckbox.Outbound;

/// <summary>
/// A message sealed for one recipient: encrypted with AES-256-GCM under a key agreed by ECDH on P-256 between a key made for
/// this message and the recipient's public key, so what travels, including through a proxy that inspects TLS, cannot be read
/// by anyone else. The ephemeral key also lets the recipient seal its answer for the sender.
/// </summary>
/// <param name="EphemeralPublicKey">Base64 of the SubjectPublicKeyInfo of the key made for this message.</param>
/// <param name="Nonce">Base64 of the 12-byte nonce.</param>
/// <param name="Ciphertext">Base64 of the ciphertext followed by its 16-byte authentication tag.</param>
public sealed record SealedEnvelope(int Version, string EphemeralPublicKey, string Nonce, string Ciphertext);

/// <summary>A sealed answer and the signature of the instance that made it (ES256 over the envelope and what it is bound to).</summary>
public sealed record SignedEnvelope(SealedEnvelope Envelope, string Signature);

public static class EnvelopeSealer
{
    public const int CurrentVersion = 1;

    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private static readonly byte[] Label = "teeckbox-agent-envelope-v1"u8.ToArray();

    /// <summary>
    /// Seals <paramref name="plaintext"/> for the holder of the private key of <paramref name="recipientPublicKey"/>.
    /// <paramref name="aad"/> is authenticated but not sent: the recipient must give the same bytes to open it, which binds the
    /// message to its call and to its recipient. The caller keeps <paramref name="ephemeral"/> to open the answer, then disposes it.
    /// </summary>
    /// <param name="recipientPublicKey">Base64 of the SubjectPublicKeyInfo of a P-256 key.</param>
    /// <exception cref="CryptographicException">The recipient's key is not a P-256 public key.</exception>
    public static SealedEnvelope Seal(ReadOnlySpan<byte> plaintext, string recipientPublicKey, ReadOnlySpan<byte> aad, out ECDiffieHellman ephemeral)
    {
        using var recipient = ImportPublicKey(recipientPublicKey);
        ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        try
        {
            var ephemeralInfo = ephemeral.ExportSubjectPublicKeyInfo();
            var key = DeriveKey(ephemeral.DeriveRawSecretAgreement(recipient.PublicKey), ephemeralInfo, recipient.ExportSubjectPublicKeyInfo());
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var ciphertext = new byte[plaintext.Length + TagBytes];
            using (var aes = new AesGcm(key, TagBytes))
            {
                aes.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, plaintext.Length), ciphertext.AsSpan(plaintext.Length, TagBytes), aad);
            }

            CryptographicOperations.ZeroMemory(key);
            return new SealedEnvelope(CurrentVersion, Convert.ToBase64String(ephemeralInfo), Convert.ToBase64String(nonce), Convert.ToBase64String(ciphertext));
        }
        catch
        {
            ephemeral.Dispose();
            throw;
        }
    }

    /// <summary>Opens an envelope sealed for <paramref name="recipient"/>, with the same <paramref name="aad"/> it was sealed with.</summary>
    /// <exception cref="CryptographicException">The envelope was not sealed for this key, was changed, or is bound to something else.</exception>
    public static byte[] Open(SealedEnvelope envelope, ECDiffieHellman recipient, ReadOnlySpan<byte> aad)
    {
        try
        {
            if (envelope.Version != CurrentVersion)
            {
                throw new CryptographicException("Unknown envelope version.");
            }

            var ephemeralInfo = Convert.FromBase64String(envelope.EphemeralPublicKey);
            var nonce = Convert.FromBase64String(envelope.Nonce);
            var sealedBytes = Convert.FromBase64String(envelope.Ciphertext);
            if (nonce.Length != NonceBytes || sealedBytes.Length < TagBytes)
            {
                throw new CryptographicException("The envelope is malformed.");
            }

            using var sender = ImportPublicKey(envelope.EphemeralPublicKey);
            var key = DeriveKey(recipient.DeriveRawSecretAgreement(sender.PublicKey), ephemeralInfo, recipient.ExportSubjectPublicKeyInfo());
            var plaintext = new byte[sealedBytes.Length - TagBytes];
            using (var aes = new AesGcm(key, TagBytes))
            {
                aes.Decrypt(nonce, sealedBytes.AsSpan(0, plaintext.Length), sealedBytes.AsSpan(plaintext.Length, TagBytes), plaintext, aad);
            }

            CryptographicOperations.ZeroMemory(key);
            return plaintext;
        }
        catch (FormatException error)
        {
            throw new CryptographicException("The envelope is malformed.", error);
        }
    }

    /// <summary>The bytes an envelope is bound to for a call: its identifier, its recipient, and which way it travels.</summary>
    public static byte[] Binding(string callId, Guid instanceId, string direction) =>
        Encoding.UTF8.GetBytes($"{callId}|{instanceId:N}|{direction}");

    /// <summary>Whether the text is the base64 of the SubjectPublicKeyInfo of a P-256 public key.</summary>
    public static bool IsPublicKey(string? text)
    {
        try
        {
            using var key = ImportPublicKey(text);
            return true;
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    private static ECDiffieHellman ImportPublicKey(string? text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        var key = ECDiffieHellman.Create();
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

    private static byte[] DeriveKey(byte[] sharedSecret, byte[] ephemeralInfo, byte[] recipientInfo)
    {
        var info = new byte[Label.Length + ephemeralInfo.Length + recipientInfo.Length];
        Label.CopyTo(info, 0);
        ephemeralInfo.CopyTo(info, Label.Length);
        recipientInfo.CopyTo(info, Label.Length + ephemeralInfo.Length);
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, KeyBytes, salt: null, info: info);
        CryptographicOperations.ZeroMemory(sharedSecret);
        return key;
    }
}
