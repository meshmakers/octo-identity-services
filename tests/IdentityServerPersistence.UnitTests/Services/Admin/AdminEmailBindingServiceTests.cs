using FluentAssertions;
using IdentityServerPersistence.Services.Admin;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.Admin;

/// <summary>
///     Pins the admin e-mail verified-whitelist write (AB#5125): binding an address stores a
///     <c>VerifiedExternalIdentifier(EmailAddress, Strong, Admin)</c> through the AB#5122 resolver,
///     with the address normalized (trimmed + lower-cased) and <c>RequiredMessageAuthentication</c>
///     set so the binding records the DKIM/DMARC expectation. An invalid address never writes; an
///     unknown user surfaces as a clean status rather than an exception.
/// </summary>
public class AdminEmailBindingServiceTests
{
    private readonly IVerifiedIdentifierResolver _resolver = Substitute.For<IVerifiedIdentifierResolver>();
    private readonly AdminEmailBindingService _service;
    private readonly OctoObjectId _userRtId = OctoObjectId.GenerateNewId();

    public AdminEmailBindingServiceTests()
    {
        _resolver.StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>()).Returns(OctoObjectId.GenerateNewId());
        _service = new AdminEmailBindingService(_resolver, Substitute.For<ILogger<AdminEmailBindingService>>());
    }

    [Fact]
    public async Task Binding_a_valid_address_stores_it_Strong_Admin_and_normalized()
    {
        var result = await _service.BindEmailAsync(_userRtId, "  Vendor@Example.COM ");

        result.Status.Should().Be(AdminBindEmailStatus.Bound);
        result.NormalizedEmail.Should().Be("vendor@example.com");

        await _resolver.Received(1).StoreBindingAsync(Arg.Is<VerifiedIdentifierBinding>(b =>
            b.IdentifierKind == RtIdentifierKindEnum.EmailAddress &&
            b.IdentifierValue == "vendor@example.com" &&
            b.UserRtId == _userRtId &&
            b.EnrollmentTrust == RtTrustLevelEnum.Strong &&
            b.Source == RtIdentifierSourceEnum.Admin &&
            b.RequiredMessageAuthentication));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-email")]
    [InlineData("Vendor <vendor@example.com>")]
    [InlineData("a@b@c.com")]
    public async Task An_invalid_address_never_writes(string raw)
    {
        var result = await _service.BindEmailAsync(_userRtId, raw);

        result.Status.Should().Be(AdminBindEmailStatus.InvalidEmail);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task An_unknown_user_surfaces_as_UserNotFound()
    {
        _resolver.StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>())
            .Returns<OctoObjectId>(_ => throw new NotExistingException("nope"));

        var result = await _service.BindEmailAsync(_userRtId, "vendor@example.com");

        result.Status.Should().Be(AdminBindEmailStatus.UserNotFound);
    }

    [Fact]
    public async Task Removing_normalizes_the_address_before_it_deletes()
    {
        _resolver.RemoveBindingAsync(RtIdentifierKindEnum.EmailAddress, "vendor@example.com").Returns(true);

        var removed = await _service.RemoveAsync("  VENDOR@example.com ");

        removed.Should().BeTrue();
        await _resolver.Received(1)
            .RemoveBindingAsync(RtIdentifierKindEnum.EmailAddress, "vendor@example.com");
    }

    [Fact]
    public async Task Listing_reads_the_email_kind_from_the_directory()
    {
        _resolver.GetByKindAsync(RtIdentifierKindEnum.EmailAddress)
            .Returns(new List<VerifiedIdentifierWithUser>());

        await _service.ListAsync();

        await _resolver.Received(1).GetByKindAsync(RtIdentifierKindEnum.EmailAddress);
    }
}
