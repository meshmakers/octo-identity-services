using FluentAssertions;
using Duende.IdentityServer.Models;
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

        // Reference: the exact extension Duende-based code paths used to store secrets.
        OctoSecretHasher.HashSecret(secret).Should().Be(secret.Sha256());
    }

    [Fact]
    public void Matches_AcceptsDuendeSha256StoredHash()
    {
        const string secret = "golden-machine-secret";
        OctoSecretHasher.Matches(secret, secret.Sha256()).Should().BeTrue();
    }

    [Fact]
    public void Matches_AcceptsDuendeSha512StoredHash()
    {
        const string secret = "golden-machine-secret";
        OctoSecretHasher.Matches(secret, secret.Sha512()).Should().BeTrue();
    }

    [Fact]
    public void Matches_RejectsWrongSecret()
    {
        OctoSecretHasher.Matches("wrong", "right".Sha256()).Should().BeFalse();
    }

    [Fact]
    public void Matches_RejectsEmptyInputs()
    {
        OctoSecretHasher.Matches("", "x".Sha256()).Should().BeFalse();
        OctoSecretHasher.Matches("x", "").Should().BeFalse();
    }
}
