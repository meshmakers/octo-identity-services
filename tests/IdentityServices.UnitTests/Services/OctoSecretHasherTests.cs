using FluentAssertions;
using System.Security.Cryptography;
using System.Text;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     Pins the legacy secret-hash compatibility contract of <see cref="OctoSecretHasher" />
///     (AB#4991): every stored <c>RtSecretRecord.Value</c> was written by the pre-migration
///     IdentityServer as Base64 of the SHA-256/SHA-512 of the plain secret — the OpenIddict
///     application manager must keep matching those hashes so no client has to rotate its secret
///     at the cutover.
/// </summary>
public class OctoSecretHasherTests
{
    [Fact]
    public void HashSecret_ProducesLegacySha256Format()
    {
        const string secret = "my-service-account-secret";

        // Reference: the pre-migration IdentityServer stored Base64(SHA-256(UTF8(secret))).
        OctoSecretHasher.HashSecret(secret).Should().Be(LegacySha256(secret));
    }

    [Fact]
    public void Matches_AcceptsLegacySha256StoredHash()
    {
        const string secret = "golden-machine-secret";
        OctoSecretHasher.Matches(secret, LegacySha256(secret)).Should().BeTrue();
    }

    [Fact]
    public void Matches_AcceptsLegacySha512StoredHash()
    {
        const string secret = "golden-machine-secret";
        OctoSecretHasher.Matches(secret, LegacySha512(secret)).Should().BeTrue();
    }

    [Fact]
    public void Matches_RejectsWrongSecret()
    {
        OctoSecretHasher.Matches("wrong", LegacySha256("right")).Should().BeFalse();
    }

    [Fact]
    public void Matches_RejectsEmptyInputs()
    {
        OctoSecretHasher.Matches("", LegacySha256("x")).Should().BeFalse();
        OctoSecretHasher.Matches("x", "").Should().BeFalse();
    }

    /// <summary>Reference implementation of the legacy SHA-256 secret-hash format.</summary>
    private static string LegacySha256(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Reference implementation of the legacy SHA-512 secret-hash format.</summary>
    private static string LegacySha512(string value)
        => Convert.ToBase64String(SHA512.HashData(Encoding.UTF8.GetBytes(value)));
}
