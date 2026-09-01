using FluentAssertions;
using System.Security.Cryptography;
using System.Text;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     Pins the Duende-hash compatibility contract of <see cref="OctoSecretHasher" /> (AB#4991):
///     every stored <c>RtSecretRecord.Value</c> was produced by Duende's
///     <c>HashExtensions.Sha256()</c>/<c>.Sha512()</c> — the OpenIddict application manager must
///     keep matching those hashes so no client has to rotate its secret at the cutover.
/// </summary>
public class OctoSecretHasherTests
{
    [Fact]
    public void HashSecret_ProducesDuendeSha256Format()
    {
        const string secret = "my-service-account-secret";

        // Reference: Duende's HashExtensions.Sha256() stored Base64(SHA-256(UTF8(secret))).
        OctoSecretHasher.HashSecret(secret).Should().Be(DuendeSha256(secret));
    }

    [Fact]
    public void Matches_AcceptsDuendeSha256StoredHash()
    {
        const string secret = "golden-machine-secret";
        OctoSecretHasher.Matches(secret, DuendeSha256(secret)).Should().BeTrue();
    }

    [Fact]
    public void Matches_AcceptsDuendeSha512StoredHash()
    {
        const string secret = "golden-machine-secret";
        OctoSecretHasher.Matches(secret, DuendeSha512(secret)).Should().BeTrue();
    }

    [Fact]
    public void Matches_RejectsWrongSecret()
    {
        OctoSecretHasher.Matches("wrong", DuendeSha256("right")).Should().BeFalse();
    }

    [Fact]
    public void Matches_RejectsEmptyInputs()
    {
        OctoSecretHasher.Matches("", DuendeSha256("x")).Should().BeFalse();
        OctoSecretHasher.Matches("x", "").Should().BeFalse();
    }

    /// <summary>Reference implementation of Duende's HashExtensions.Sha256().</summary>
    private static string DuendeSha256(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Reference implementation of Duende's HashExtensions.Sha512().</summary>
    private static string DuendeSha512(string value)
        => Convert.ToBase64String(SHA512.HashData(Encoding.UTF8.GetBytes(value)));
}
