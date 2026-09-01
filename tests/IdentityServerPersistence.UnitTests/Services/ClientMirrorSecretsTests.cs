using FluentAssertions;
using IdentityServerPersistence.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     The primitives behind per-tenant mirror secrets (AB#5061).
/// </summary>
public class ClientMirrorSecretsTests
{
    /// <summary>
    ///     🔴 Pins the hash convention. <see cref="ClientMirrorSecrets.Sha256" /> reimplements
    ///     Duende's <c>string.Sha256()</c> so the persistence layer stays free of a protocol
    ///     dependency (Epic 4989 / OpenIddict). If the two ever diverge, a rotated mirror secret
    ///     would be stored in a shape the token endpoint cannot match, and the credential would
    ///     silently never work. The expected values are the published SHA-256 digests, base64
    ///     encoded — i.e. an external reference, not a copy of our own output.
    /// </summary>
    [Theory]
    [InlineData("", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
    [InlineData("abc", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")]
    [InlineData("The quick brown fox jumps over the lazy dog",
        "16j7swfXgJRpypq8sAguT41WUeRtPNt2LQLQvzfJ5ZI=")]
    public void Sha256_MatchesThePublishedDigest(string input, string expectedBase64)
    {
        ClientMirrorSecrets.Sha256(input).Should().Be(expectedBase64);
    }

    [Fact]
    public void GenerateSecret_ProducesDistinctUrlSafeValues()
    {
        var secrets = Enumerable.Range(0, 200).Select(_ => ClientMirrorSecrets.GenerateSecret()).ToList();

        secrets.Should().OnlyHaveUniqueItems();
        secrets.Should().AllSatisfy(s =>
        {
            // 32 random bytes, base64url without padding.
            s.Length.Should().Be(43);
            s.Should().MatchRegex("^[A-Za-z0-9_-]+$",
                "the value travels through env vars, form bodies and shell quoting unescaped");
        });
    }

    [Fact]
    public void CreateOwnSecretRecord_StoresOnlyTheHash_AndTagsTheRecord()
    {
        const string plaintext = "s3cret-value";

        var record = ClientMirrorSecrets.CreateOwnSecretRecord(plaintext);

        record.Value.Should().NotBe(plaintext, "a plaintext secret must never be persisted");
        record.Value.Should().Be(ClientMirrorSecrets.Sha256(plaintext));
        record.Description.Should().Be(ClientMirrorSecrets.OwnSecretDescription);
        ClientMirrorSecrets.IsOwnSecret(record).Should().BeTrue();
    }

    [Fact]
    public void IsOwnSecret_IsFalseForAnInheritedParentSecret()
    {
        var inherited = new RtSecretRecord
        {
            Type = ClientMirrorSecrets.SharedSecretType,
            Value = "parent-hash"
        };

        ClientMirrorSecrets.IsOwnSecret(inherited).Should().BeFalse();
    }

    /// <summary>
    ///     Either signal alone makes a client confidential. <c>RequireClientSecret</c> is the
    ///     declared intent and can precede the first secret; a populated list is the material
    ///     itself, which secret validation honours even when the flag was switched off afterwards.
    ///     Reading only one of them would leave a way to construct the very state being guarded.
    /// </summary>
    [Theory]
    [InlineData(false, false, false)]
    [InlineData(true, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, true, true)]
    public void IsConfidential_ConsidersBothTheFlagAndTheMaterial(
        bool requireSecret, bool hasSecret, bool expected)
    {
        var builder = new RtClientBuilder().RequireClientSecret(requireSecret);
        if (hasSecret)
        {
            builder.WithSecret(ClientMirrorSecrets.SharedSecretType, "some-hash");
        }

        ClientMirrorSecrets.IsConfidential(builder.Build()).Should().Be(expected);
    }

    [Fact]
    public void FindOwnSecret_ReturnsNullWhenTheMirrorPredatesTheFeature()
    {
        var legacyMirror = new RtClientBuilder()
            .RequireClientSecret()
            .WithSecret(ClientMirrorSecrets.SharedSecretType, "inherited-parent-hash")
            .Build();

        ClientMirrorSecrets.FindOwnSecret(legacyMirror).Should().BeNull();
    }
}
