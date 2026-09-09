using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.CkModel;

/// <summary>
///     Schema-level checks for the AB#5122 verified external identifier directory: the
///     <c>RtVerifiedExternalIdentifier</c> CK type, its enum attributes and their safe defaults, and
///     the <see cref="TrustLevels.Min" /> helper that encodes the effective-trust rule
///     <c>effective = min(enrollment, message)</c>. Locking these down keeps a CK-model regression
///     (a YAML rename or a reordered enum) from silently changing the trust semantics.
/// </summary>
public class VerifiedExternalIdentifierSchemaTests
{
    [Fact]
    public void NewBinding_Defaults_AreTheSafeMinimums()
    {
        var binding = new RtVerifiedExternalIdentifier();

        // PhoneNumber(0), None(0), SelfService(0), false — the least-trusting, least-privileged start.
        binding.IdentifierKind.Should().Be(RtIdentifierKindEnum.PhoneNumber);
        binding.EnrollmentTrust.Should().Be(RtTrustLevelEnum.None);
        binding.Source.Should().Be(RtIdentifierSourceEnum.SelfService);
        binding.RequiredMessageAuthentication.Should().BeFalse();
    }

    [Fact]
    public void Binding_HoldsAllModeledAttributes()
    {
        var enrolledAt = new DateTime(2026, 9, 4, 8, 0, 0, DateTimeKind.Utc);
        var verifiedAt = new DateTime(2026, 9, 4, 9, 0, 0, DateTimeKind.Utc);

        var binding = new RtVerifiedExternalIdentifier
        {
            IdentifierKind = RtIdentifierKindEnum.EmailAddress,
            IdentifierValue = "alice@example.com",
            EnrollmentTrust = RtTrustLevelEnum.Strong,
            RequiredMessageAuthentication = true,
            Source = RtIdentifierSourceEnum.IdentityProvider,
            EnrolledAt = enrolledAt,
            LastVerifiedAt = verifiedAt
        };

        binding.IdentifierKind.Should().Be(RtIdentifierKindEnum.EmailAddress);
        binding.IdentifierValue.Should().Be("alice@example.com");
        binding.EnrollmentTrust.Should().Be(RtTrustLevelEnum.Strong);
        binding.RequiredMessageAuthentication.Should().BeTrue();
        binding.Source.Should().Be(RtIdentifierSourceEnum.IdentityProvider);
        binding.EnrolledAt.Should().Be(enrolledAt);
        binding.LastVerifiedAt.Should().Be(verifiedAt);
    }

    [Fact]
    public void TrustScale_IsTotallyOrdered_NoneWeakStrong()
    {
        // The numeric keys carry the order the min relies on.
        ((int)RtTrustLevelEnum.None).Should().BeLessThan((int)RtTrustLevelEnum.Weak);
        ((int)RtTrustLevelEnum.Weak).Should().BeLessThan((int)RtTrustLevelEnum.Strong);
    }

    [Fact]
    public void IdentifierKind_HasTheFourModeledKinds()
    {
        ((int)RtIdentifierKindEnum.PhoneNumber).Should().Be(0);
        ((int)RtIdentifierKindEnum.EmailAddress).Should().Be(1);
        ((int)RtIdentifierKindEnum.EntraIdObjectId).Should().Be(2);
        ((int)RtIdentifierKindEnum.ClientCertificateFingerprint).Should().Be(3);
    }

    [Theory]
    // effective = min(enrollment, message) across every combination.
    [InlineData(RtTrustLevelEnum.Strong, RtTrustLevelEnum.Strong, RtTrustLevelEnum.Strong)]
    [InlineData(RtTrustLevelEnum.Strong, RtTrustLevelEnum.Weak, RtTrustLevelEnum.Weak)]
    [InlineData(RtTrustLevelEnum.Weak, RtTrustLevelEnum.Strong, RtTrustLevelEnum.Weak)]
    [InlineData(RtTrustLevelEnum.Strong, RtTrustLevelEnum.None, RtTrustLevelEnum.None)]
    [InlineData(RtTrustLevelEnum.None, RtTrustLevelEnum.Strong, RtTrustLevelEnum.None)]
    [InlineData(RtTrustLevelEnum.Weak, RtTrustLevelEnum.Weak, RtTrustLevelEnum.Weak)]
    [InlineData(RtTrustLevelEnum.None, RtTrustLevelEnum.None, RtTrustLevelEnum.None)]
    public void TrustLevels_Min_ReturnsTheWeakerDimension(
        RtTrustLevelEnum enrollment, RtTrustLevelEnum message, RtTrustLevelEnum expected)
    {
        TrustLevels.Min(enrollment, message).Should().Be(expected);
    }

    [Fact]
    public void TrustLevels_Min_IsCommutative()
    {
        TrustLevels.Min(RtTrustLevelEnum.Strong, RtTrustLevelEnum.Weak)
            .Should().Be(TrustLevels.Min(RtTrustLevelEnum.Weak, RtTrustLevelEnum.Strong));
    }
}
