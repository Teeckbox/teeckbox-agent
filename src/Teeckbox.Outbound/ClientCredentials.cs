using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Teeckbox.Outbound;

/// <summary>HTTP headers typed one per line as <c>Name: value</c>, for the requests of a datasource.</summary>
public static partial class HttpHeaderLines
{
    public const int MaxHeaders = 20;

    /// <summary>Headers the HTTP client sets itself, or that would change how the request travels.</summary>
    private static readonly HashSet<string> Refused = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive", "Upgrade", "TE", "Trailer",
        "Proxy-Authorization", "Proxy-Connection",
    };

    /// <summary>The headers of the text, in order; blank lines are ignored.</summary>
    /// <exception cref="FormatException">A line is not a header Teeckbox may send.</exception>
    public static IReadOnlyList<KeyValuePair<string, string>> Parse(string text)
    {
        var headers = new List<KeyValuePair<string, string>>();
        foreach (var line in text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0))
        {
            var colon = line.IndexOf(':');
            var name = colon > 0 ? line[..colon].Trim() : "";
            var value = colon > 0 ? line[(colon + 1)..].Trim() : "";
            if (!NamePattern().IsMatch(name) || value.Any(char.IsControl))
            {
                throw new FormatException($"\"{Shorten(line)}\" is not a header: write one Name: value per line.");
            }

            if (Refused.Contains(name))
            {
                throw new FormatException($"The header {name} cannot be set.");
            }

            headers.Add(new(name, value));
        }

        return headers.Count <= MaxHeaders ? headers : throw new FormatException($"At most {MaxHeaders} headers can be set.");
    }

    /// <summary>Why the text cannot be read as headers, or <c>null</c>.</summary>
    public static string? Check(string text)
    {
        try
        {
            Parse(text);
            return null;
        }
        catch (FormatException error)
        {
            return error.Message;
        }
    }

    // A secret value must not appear in an error message.
    private static string Shorten(string line) => line.Length <= 20 ? line : line[..20] + "…";

    /// <summary>An HTTP token (RFC 9110).</summary>
    [GeneratedRegex(@"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")]
    private static partial Regex NamePattern();
}

/// <summary>A private key that signs client assertions (RFC 7523), with the certificate that identifies it, if any.</summary>
public sealed class SigningKey(AsymmetricAlgorithm key, string algorithm, X509Certificate2? certificate) : IDisposable
{
    public AsymmetricAlgorithm Key { get; } = key;

    /// <summary>The JWS algorithm: RS256, ES256, ES384 or ES512.</summary>
    public string Algorithm { get; } = algorithm;

    public X509Certificate2? Certificate { get; } = certificate;

    public byte[] Sign(byte[] data) => Key switch
    {
        RSA rsa => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
        // .NET signs with ECDSA in the IEEE P1363 format that JWS expects.
        ECDsa ec => ec.SignData(data, Algorithm switch { "ES384" => HashAlgorithmName.SHA384, "ES512" => HashAlgorithmName.SHA512, _ => HashAlgorithmName.SHA256 }),
        _ => throw new CryptographicException("Unsupported key."),
    };

    public void Dispose()
    {
        Key.Dispose();
        Certificate?.Dispose();
    }
}

/// <summary>
/// Keys and certificates pasted as PEM by an administrator, for OAuth client assertions and mutual
/// TLS. Encrypted private keys are refused: the PEM is itself stored encrypted by the caller.
/// </summary>
public static class ClientKeys
{
    private const string Encrypted = "The private key is protected by a password; paste it without a password. Teeckbox stores it encrypted.";

    /// <summary>The RSA or EC private key of the PEM, and the certificate that follows it, if any.</summary>
    /// <exception cref="CryptographicException">No usable private key, or a certificate that does not match it.</exception>
    public static SigningKey ReadSigningKey(string pem)
    {
        pem = Separate(pem);
        string? keyPem = null, keyLabel = null, certificatePem = null;
        foreach (var (label, text) in Blocks(pem))
        {
            switch (label)
            {
                case "ENCRYPTED PRIVATE KEY":
                    throw new CryptographicException(Encrypted);
                case "PRIVATE KEY" or "RSA PRIVATE KEY" or "EC PRIVATE KEY" when keyPem is null:
                    (keyPem, keyLabel) = (text, label);
                    break;
                case "CERTIFICATE" when certificatePem is null:
                    certificatePem = text;
                    break;
            }
        }

        if (keyPem is null)
        {
            throw new CryptographicException("Paste a PEM private key, starting with -----BEGIN PRIVATE KEY-----.");
        }

        AsymmetricAlgorithm key = keyLabel switch
        {
            "RSA PRIVATE KEY" => ImportRsa(keyPem),
            "EC PRIVATE KEY" => ImportEc(keyPem),
            _ => (AsymmetricAlgorithm?)TryImportRsa(keyPem) ?? ImportEc(keyPem),
        };

        var algorithm = key switch
        {
            RSA => "RS256",
            ECDsa { KeySize: 384 } => "ES384",
            ECDsa { KeySize: 521 } => "ES512",
            ECDsa { KeySize: 256 } => "ES256",
            _ => null,
        };
        if (algorithm is null)
        {
            key.Dispose();
            throw new CryptographicException("Use an RSA key or an EC key on the P-256, P-384 or P-521 curve.");
        }

        X509Certificate2? certificate = null;
        if (certificatePem is not null)
        {
            certificate = X509Certificate2.CreateFromPem(certificatePem);
            if (!certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()))
            {
                certificate.Dispose();
                key.Dispose();
                throw new CryptographicException("The certificate does not belong to the private key.");
            }
        }

        return new SigningKey(key, algorithm, certificate);
    }

    /// <summary>The certificate of the PEM with its private key, ready to be presented in a TLS handshake.</summary>
    /// <exception cref="CryptographicException">No certificate, no private key, or keys that do not match.</exception>
    public static X509Certificate2 ReadCertificate(string pem)
    {
        pem = Separate(pem);
        var labels = Blocks(pem).Select(b => b.Label).ToList();
        if (labels.Contains("ENCRYPTED PRIVATE KEY"))
        {
            throw new CryptographicException(Encrypted);
        }

        if (!labels.Contains("CERTIFICATE") || !labels.Any(l => l is "PRIVATE KEY" or "RSA PRIVATE KEY" or "EC PRIVATE KEY"))
        {
            throw new CryptographicException("Paste the PEM certificate followed by its private key.");
        }

        using var loaded = X509Certificate2.CreateFromPem(pem, pem);
        // A key imported from PEM is ephemeral, which Windows refuses in a TLS handshake: a PKCS#12 round trip gives it a key container.
        return X509CertificateLoader.LoadPkcs12(loaded.Export(X509ContentType.Pkcs12), null);
    }

    /// <summary>Why the PEM is not a usable private key, or <c>null</c>.</summary>
    public static string? CheckSigningKey(string pem) => Check(() => ReadSigningKey(pem).Dispose());

    /// <summary>Why the PEM is not a usable client certificate, or <c>null</c>.</summary>
    public static string? CheckCertificate(string pem) => Check(() => ReadCertificate(pem).Dispose());

    private static string? Check(Action read)
    {
        try
        {
            read();
            return null;
        }
        catch (CryptographicException error)
        {
            return error.Message;
        }
        catch (ArgumentException)
        {
            return "The PEM text cannot be read.";
        }
    }

    /// <summary>Blocks pasted one after the other without a line break between them.</summary>
    private static string Separate(string pem) => pem.Replace("----------BEGIN ", "-----\n-----BEGIN ", StringComparison.Ordinal);

    private static IEnumerable<(string Label, string Text)> Blocks(string pem)
    {
        var rest = pem;
        while (PemEncoding.TryFind(rest, out var fields))
        {
            yield return (rest[fields.Label].ToString(), rest[fields.Location].ToString());
            rest = rest[fields.Location.End..];
        }
    }

    private static RSA ImportRsa(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    private static RSA? TryImportRsa(string pem)
    {
        try
        {
            return ImportRsa(pem);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static ECDsa ImportEc(string pem)
    {
        var ec = ECDsa.Create();
        ec.ImportFromPem(pem);
        return ec;
    }
}
