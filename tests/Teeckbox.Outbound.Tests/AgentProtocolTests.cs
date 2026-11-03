using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Teeckbox.Outbound.Tests;

/// <summary>What travels between Teeckbox and an agent: sealed envelopes, signed answers, connection tokens, key rotation.</summary>
public class AgentProtocolTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 3, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid Instance = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private const string Audience = "https://teeckbox.example.com";

    private static (ECDiffieHellman Key, string Public) NewEncryptionKey()
    {
        var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return (key, AgentKeys.PublicKeyOf(key));
    }

    private static (ECDsa Key, string Public) NewSigningKey()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (key, AgentKeys.PublicKeyOf(key));
    }

    // ---- Sealed envelopes ----

    [Fact]
    public void A_message_sealed_for_an_instance_is_opened_by_that_instance()
    {
        var (agent, agentPublic) = NewEncryptionKey();
        var binding = EnvelopeSealer.Binding("call-1", Instance, "request");

        var envelope = EnvelopeSealer.Seal("a password: hunter2"u8, agentPublic, binding, out var ephemeral);
        using (ephemeral)
        {
            Assert.Equal("a password: hunter2", Encoding.UTF8.GetString(EnvelopeSealer.Open(envelope, agent, binding)));
        }

        Assert.DoesNotContain("hunter2", envelope.Ciphertext);
        Assert.DoesNotContain("hunter2", Encoding.UTF8.GetString(Convert.FromBase64String(envelope.Ciphertext), 0, 5));
    }

    [Fact]
    public void Two_envelopes_of_the_same_message_differ()
    {
        var (_, agentPublic) = NewEncryptionKey();
        var binding = EnvelopeSealer.Binding("call-1", Instance, "request");

        var first = EnvelopeSealer.Seal("same"u8, agentPublic, binding, out var e1);
        var second = EnvelopeSealer.Seal("same"u8, agentPublic, binding, out var e2);
        e1.Dispose();
        e2.Dispose();

        Assert.NotEqual(first.Ciphertext, second.Ciphertext);
        Assert.NotEqual(first.EphemeralPublicKey, second.EphemeralPublicKey);
        Assert.NotEqual(first.Nonce, second.Nonce);
    }

    [Fact]
    public void Another_instance_cannot_open_it()
    {
        var (_, agentPublic) = NewEncryptionKey();
        var (other, _) = NewEncryptionKey();
        var binding = EnvelopeSealer.Binding("call-1", Instance, "request");
        var envelope = EnvelopeSealer.Seal("secret"u8, agentPublic, binding, out var ephemeral);
        ephemeral.Dispose();

        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope, other, binding));
    }

    [Fact]
    public void An_envelope_is_bound_to_its_call_its_instance_and_its_direction()
    {
        var (agent, agentPublic) = NewEncryptionKey();
        var envelope = EnvelopeSealer.Seal("secret"u8, agentPublic, EnvelopeSealer.Binding("call-1", Instance, "request"), out var ephemeral);
        ephemeral.Dispose();

        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope, agent, EnvelopeSealer.Binding("call-2", Instance, "request")));
        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope, agent, EnvelopeSealer.Binding("call-1", Guid.NewGuid(), "request")));
        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope, agent, EnvelopeSealer.Binding("call-1", Instance, "response")));
    }

    [Fact]
    public void A_changed_envelope_is_refused()
    {
        var (agent, agentPublic) = NewEncryptionKey();
        var binding = EnvelopeSealer.Binding("call-1", Instance, "request");
        var envelope = EnvelopeSealer.Seal("secret"u8, agentPublic, binding, out var ephemeral);
        ephemeral.Dispose();
        var bytes = Convert.FromBase64String(envelope.Ciphertext);
        bytes[0] ^= 1;

        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope with { Ciphertext = Convert.ToBase64String(bytes) }, agent, binding));
        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope with { Nonce = Convert.ToBase64String(new byte[12]) }, agent, binding));
        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope with { Ciphertext = "not base64 !" }, agent, binding));
        Assert.ThrowsAny<CryptographicException>(() => EnvelopeSealer.Open(envelope with { Version = 2 }, agent, binding));
    }

    [Fact]
    public void The_answer_is_sealed_back_for_the_sender_and_signed_by_the_instance()
    {
        var (agentEncryption, agentEncryptionPublic) = NewEncryptionKey();
        var (agentSigning, agentSigningPublic) = NewSigningKey();
        var request = EnvelopeSealer.Seal("question"u8, agentEncryptionPublic, EnvelopeSealer.Binding("c", Instance, "request"), out var serverEphemeral);
        using var _ = serverEphemeral;
        using var __ = agentEncryption;
        using var ___ = agentSigning;

        // The agent seals the answer for the ephemeral key the request came with, and signs it.
        var responseBinding = EnvelopeSealer.Binding("c", Instance, "response");
        var answer = EnvelopeSealer.Seal("answer"u8, request.EphemeralPublicKey, responseBinding, out var agentEphemeral);
        agentEphemeral.Dispose();
        var signature = AgentSignature.Sign(answer, responseBinding, agentSigning);

        Assert.True(AgentSignature.Verify(answer, responseBinding, signature, agentSigningPublic));
        Assert.Equal("answer", Encoding.UTF8.GetString(EnvelopeSealer.Open(answer, serverEphemeral, responseBinding)));
    }

    [Fact]
    public void An_answer_not_signed_by_the_instance_is_refused()
    {
        var (agentSigning, agentSigningPublic) = NewSigningKey();
        var (attacker, _) = NewSigningKey();
        var (_, serverPublic) = NewEncryptionKey();
        var binding = EnvelopeSealer.Binding("c", Instance, "response");
        var answer = EnvelopeSealer.Seal("forged"u8, serverPublic, binding, out var ephemeral);
        ephemeral.Dispose();
        using var _1 = agentSigning;
        using var _2 = attacker;

        Assert.False(AgentSignature.Verify(answer, binding, AgentSignature.Sign(answer, binding, attacker), agentSigningPublic));
        Assert.False(AgentSignature.Verify(answer, EnvelopeSealer.Binding("other", Instance, "response"), AgentSignature.Sign(answer, binding, agentSigning), agentSigningPublic));
        Assert.False(AgentSignature.Verify(answer, binding, "not base64", agentSigningPublic));
    }

    [Fact]
    public void Only_p256_public_keys_are_accepted()
    {
        using var p384 = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        using var rsa = RSA.Create(2048);
        var binding = EnvelopeSealer.Binding("c", Instance, "request");

        Assert.True(EnvelopeSealer.IsPublicKey(NewEncryptionKey().Public));
        Assert.False(EnvelopeSealer.IsPublicKey(Convert.ToBase64String(p384.ExportSubjectPublicKeyInfo())));
        Assert.False(EnvelopeSealer.IsPublicKey(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())));
        Assert.False(EnvelopeSealer.IsPublicKey("%%%"));
        Assert.False(EnvelopeSealer.IsPublicKey(null));
        Assert.ThrowsAny<Exception>(() => EnvelopeSealer.Seal("x"u8, Convert.ToBase64String(p384.ExportSubjectPublicKeyInfo()), binding, out _));
        Assert.True(AgentKeys.IsSigningPublicKey(NewSigningKey().Public));
        Assert.False(AgentKeys.IsSigningPublicKey(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo())));
    }

    [Fact]
    public void A_request_and_its_answer_travel_as_json()
    {
        var request = new AgentRequest(
            "c1",
            new AuthContext("connection:1:2", "connection \"ERP\"", new Dictionary<string, string> { ["authentication"] = "bearer" }, new Dictionary<string, string> { ["bearerToken"] = "tok" }, false),
            "GET", "https://erp.internal.example/api", "X-Tenant: acme", null, null, 10, 1_048_576);

        var back = JsonSerializer.Deserialize<AgentRequest>(JsonSerializer.Serialize(request, AgentJson.Options), AgentJson.Options)!;

        Assert.Equal("tok", back.Auth.Secrets["bearerToken"]);
        Assert.Equal("connection:1:2", back.Auth.CacheId);
        Assert.Equal("https://erp.internal.example/api", back.Url);
        Assert.Equal(AgentErrorKind.DestinationRefused, JsonSerializer.Deserialize<AgentResponse>(
            JsonSerializer.Serialize(AgentResponse.Failure("c1", AgentErrorKind.DestinationRefused, "not in the allow list"), AgentJson.Options), AgentJson.Options)!.ErrorKind);
    }

    // ---- Connection tokens ----

    [Fact]
    public void A_token_signed_by_the_instance_is_valid_for_its_audience()
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;

        var token = AgentTokens.Create(Instance, Audience, key, Now);
        var check = AgentTokens.Verify(token, publicKey, Audience, Now.AddMinutes(1));

        Assert.True(check.Valid, check.Error);
        Assert.Equal(Instance, AgentTokens.ReadSubject(token));
        Assert.False(string.IsNullOrEmpty(check.Jti));
        Assert.Equal(Now.AddMinutes(5).ToUnixTimeSeconds(), check.Expires.ToUnixTimeSeconds());
    }

    [Fact]
    public void Every_token_has_its_own_identifier()
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;

        var first = AgentTokens.Verify(AgentTokens.Create(Instance, Audience, key, Now), publicKey, Audience, Now).Jti;
        var second = AgentTokens.Verify(AgentTokens.Create(Instance, Audience, key, Now), publicKey, Audience, Now).Jti;

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void The_audience_ignores_case_and_a_trailing_slash_but_nothing_else()
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;
        var token = AgentTokens.Create(Instance, "https://Teeckbox.Example.com/", key, Now);

        Assert.True(AgentTokens.Verify(token, publicKey, Audience, Now).Valid);
        Assert.False(AgentTokens.Verify(token, publicKey, "https://other.example.com", Now).Valid);
        Assert.False(AgentTokens.Verify(token, publicKey, "http://teeckbox.example.com", Now).Valid);
    }

    [Fact]
    public void A_token_signed_with_another_key_is_refused()
    {
        var (key, _) = NewSigningKey();
        var (_, otherPublic) = NewSigningKey();
        using var _1 = key;

        Assert.False(AgentTokens.Verify(AgentTokens.Create(Instance, Audience, key, Now), otherPublic, Audience, Now).Valid);
    }

    [Fact]
    public void A_token_that_has_expired_or_comes_from_the_future_is_refused()
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;
        var token = AgentTokens.Create(Instance, Audience, key, Now);

        Assert.True(AgentTokens.Verify(token, publicKey, Audience, Now.AddMinutes(5)).Valid); // The skew covers a clock a little late.
        Assert.False(AgentTokens.Verify(token, publicKey, Audience, Now.AddMinutes(6)).Valid);
        Assert.True(AgentTokens.Verify(token, publicKey, Audience, Now.AddSeconds(-20)).Valid); // And a clock a little early.
        Assert.False(AgentTokens.Verify(token, publicKey, Audience, Now.AddMinutes(-5)).Valid);
    }

    [Fact]
    public void A_token_valid_for_more_than_five_minutes_is_refused()
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;

        var check = AgentTokens.Verify(AgentTokens.Create(Instance, Audience, key, Now, TimeSpan.FromMinutes(6)), publicKey, Audience, Now);

        Assert.False(check.Valid);
        Assert.Contains("too long", check.Error);
    }

    [Fact]
    public void A_token_that_is_altered_or_not_es256_is_refused()
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;
        var parts = AgentTokens.Create(Instance, Audience, key, Now).Split('.');
        var otherPayload = Base64Url.EncodeToString("""{"sub":"0199a1b2-0000-7000-8000-000000000001","aud":"https://teeckbox.example.com","iat":1,"exp":9999999999,"jti":"x"}"""u8);
        var none = Base64Url.EncodeToString("""{"alg":"none","typ":"JWT"}"""u8);

        Assert.False(AgentTokens.Verify($"{parts[0]}.{otherPayload}.{parts[2]}", publicKey, Audience, Now).Valid);
        Assert.False(AgentTokens.Verify($"{none}.{parts[1]}.{parts[2]}", publicKey, Audience, Now).Valid);
        Assert.False(AgentTokens.Verify($"{none}.{parts[1]}.", publicKey, Audience, Now).Valid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("a.b")]
    [InlineData("a.b.c")]
    [InlineData("not a token at all")]
    public void Garbage_is_not_a_token(string? token)
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;

        Assert.False(AgentTokens.Verify(token, publicKey, Audience, Now).Valid);
        Assert.Null(AgentTokens.ReadSubject(token));
    }

    [Fact]
    public void A_huge_token_is_refused_before_it_is_read()
    {
        var (key, publicKey) = NewSigningKey();
        using var _ = key;

        Assert.False(AgentTokens.Verify(new string('a', 5000) + ".b.c", publicKey, Audience, Now).Valid);
        Assert.Null(AgentTokens.ReadSubject(new string('a', 5000) + ".b.c"));
    }

    // ---- Key rotation ----

    [Fact]
    public void New_keys_signed_with_the_current_key_are_accepted_and_nothing_else()
    {
        var (current, currentPublic) = NewSigningKey();
        var (attacker, _) = NewSigningKey();
        var newSigning = NewSigningKey().Public;
        var newEncryption = NewEncryptionKey().Public;
        using var _1 = current;
        using var _2 = attacker;

        var signature = AgentKeyRotation.Sign(Instance, Now, newSigning, newEncryption, current);

        Assert.True(AgentKeyRotation.Verify(Instance, Now, newSigning, newEncryption, signature, currentPublic));
        Assert.False(AgentKeyRotation.Verify(Instance, Now, NewSigningKey().Public, newEncryption, signature, currentPublic));
        Assert.False(AgentKeyRotation.Verify(Instance, Now, newSigning, NewEncryptionKey().Public, signature, currentPublic));
        Assert.False(AgentKeyRotation.Verify(Guid.NewGuid(), Now, newSigning, newEncryption, signature, currentPublic));
        Assert.False(AgentKeyRotation.Verify(Instance, Now.AddSeconds(1), newSigning, newEncryption, signature, currentPublic));
        Assert.False(AgentKeyRotation.Verify(Instance, Now, newSigning, newEncryption, AgentKeyRotation.Sign(Instance, Now, newSigning, newEncryption, attacker), currentPublic));
    }

    // ---- Requests signed by Teeckbox ----

    private static (SignedRequest Request, string ServerPublic, ECDsa Server) SignedRequestFor(string callId = "call-1")
    {
        var server = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var (_, agentPublic) = NewEncryptionKey();
        var envelope = EnvelopeSealer.Seal("question"u8, agentPublic, EnvelopeSealer.Binding(callId, Instance, "request"), out var ephemeral);
        ephemeral.Dispose();
        return (AgentRequests.Sign(envelope, callId, Instance, Now, server), AgentKeys.PublicKeyOf(server), server);
    }

    [Fact]
    public void A_request_signed_by_the_server_is_accepted_for_its_call_and_its_instance()
    {
        var (request, serverPublic, server) = SignedRequestFor();
        using var _ = server;

        Assert.True(AgentRequests.Verify(request, "call-1", Instance, serverPublic, Now));
        Assert.True(AgentRequests.Verify(request, "call-1", Instance, serverPublic, Now.AddMinutes(4)));
        Assert.False(AgentRequests.Verify(request, "call-2", Instance, serverPublic, Now));
        Assert.False(AgentRequests.Verify(request, "call-1", Guid.NewGuid(), serverPublic, Now));
    }

    [Fact]
    public void A_request_signed_by_someone_else_or_changed_is_refused()
    {
        var (request, serverPublic, server) = SignedRequestFor();
        using var _ = server;
        var (other, otherPublic) = NewSigningKey();
        using var _2 = other;
        var bytes = Convert.FromBase64String(request.Envelope.Ciphertext);
        bytes[0] ^= 1;

        Assert.False(AgentRequests.Verify(request, "call-1", Instance, otherPublic, Now));
        Assert.False(AgentRequests.Verify(AgentRequests.Sign(request.Envelope, "call-1", Instance, Now, other), "call-1", Instance, serverPublic, Now));
        Assert.False(AgentRequests.Verify(request with { Envelope = request.Envelope with { Ciphertext = Convert.ToBase64String(bytes) } }, "call-1", Instance, serverPublic, Now));
        Assert.False(AgentRequests.Verify(request with { IssuedAt = request.IssuedAt + 1 }, "call-1", Instance, serverPublic, Now));
        Assert.False(AgentRequests.Verify(request with { Signature = "not base64" }, "call-1", Instance, serverPublic, Now));
        Assert.False(AgentRequests.Verify(request with { IssuedAt = long.MaxValue }, "call-1", Instance, serverPublic, Now));
    }

    [Fact]
    public void A_request_is_valid_for_five_minutes_and_not_from_the_future()
    {
        var (request, serverPublic, server) = SignedRequestFor();
        using var _ = server;

        Assert.True(AgentRequests.Verify(request, "call-1", Instance, serverPublic, Now.AddMinutes(5)));
        Assert.False(AgentRequests.Verify(request, "call-1", Instance, serverPublic, Now.AddMinutes(5).AddSeconds(1)));
        Assert.True(AgentRequests.Verify(request, "call-1", Instance, serverPublic, Now.AddMinutes(-5)));
        Assert.False(AgentRequests.Verify(request, "call-1", Instance, serverPublic, Now.AddMinutes(-6)));
    }

    [Fact]
    public void A_call_is_accepted_once_until_it_is_too_old_to_be_played_again()
    {
        var guard = new CallReplayGuard();

        Assert.True(guard.TryAccept("call-1", Now));
        Assert.False(guard.TryAccept("call-1", Now.AddMinutes(1)));
        Assert.True(guard.TryAccept("call-2", Now.AddMinutes(1)));
        // Past the window of a signed request, a replay is refused by its date; the guard can forget.
        Assert.True(guard.TryAccept("call-1", Now.AddMinutes(11)));
    }
}
