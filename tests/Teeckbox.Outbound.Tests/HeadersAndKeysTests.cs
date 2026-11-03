using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Teeckbox.Outbound.Tests;

public class HeadersAndKeysTests
{
    [Fact]
    public void Headers_are_read_one_per_line()
    {
        var headers = HttpHeaderLines.Parse("X-Tenant: acme\n\n  Accept-Language : fr-BE \r\nX-Empty:");

        Assert.Equal([new("X-Tenant", "acme"), new("Accept-Language", "fr-BE"), new("X-Empty", "")], headers);
    }

    [Theory]
    [InlineData("no colon here")]
    [InlineData("Bad Name: value")]
    [InlineData("Host: other.example.com")]
    [InlineData("content-length: 3")]
    public void Lines_that_are_not_headers_that_may_be_sent_are_refused(string text)
    {
        Assert.Throws<FormatException>(() => HttpHeaderLines.Parse(text));
        Assert.NotNull(HttpHeaderLines.Check(text));
    }

    [Fact]
    public void A_long_line_is_cut_in_the_error_so_a_secret_in_it_is_not_repeated()
    {
        var error = HttpHeaderLines.Check("Bad Name: aaaaaaaaaaaaaaaaaaaaaaaa-hunter2");

        Assert.NotNull(error);
        Assert.DoesNotContain("hunter2", error);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_private_key_and_its_certificate_can_be_read_and_sign(bool ec)
    {
        using AsymmetricAlgorithm key = ec ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : RSA.Create(2048);
        var request = key is RSA rsa
            ? new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            : new CertificateRequest("CN=test", (ECDsa)key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pem = key.ExportPkcs8PrivateKeyPem();

        using var signing = ClientKeys.ReadSigningKey(pem);

        Assert.NotEmpty(signing.Sign("data"u8.ToArray()));
        Assert.Null(ClientKeys.CheckSigningKey(pem));
        Assert.Null(ClientKeys.CheckCertificate(pem + certificate.ExportCertificatePem()));
    }

    [Fact]
    public void Text_that_is_not_a_key_is_refused_without_repeating_it()
    {
        var error = ClientKeys.CheckSigningKey("not a key, password hunter2");

        Assert.NotNull(error);
        Assert.DoesNotContain("hunter2", error);
    }
}
