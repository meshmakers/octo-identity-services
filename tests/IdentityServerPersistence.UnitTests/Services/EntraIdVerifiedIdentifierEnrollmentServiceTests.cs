using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Services.Login;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     Pins the EntraID verified-identifier auto-enrollment (AB#5124): on an EntraID login the
///     service records the <c>(EntraIdObjectId, oid) → user</c> binding with Strong enrollment trust
///     and IdentityProvider provenance, and it stays a no-op for every non-EntraID provider or a
///     token without an <c>oid</c> claim — so the mesh adapter can resolve a Teams sender's aadObjectId
///     to the right user without a separate enrollment step.
/// </summary>
public class EntraIdVerifiedIdentifierEnrollmentServiceTests
{
    private const string Oid = "11111111-2222-3333-4444-555555555555";
    private const string EntraObjectIdClaimUri = "http://schemas.microsoft.com/identity/claims/objectidentifier";

    private readonly IOctoIdentityProviderStore _providerStore = Substitute.For<IOctoIdentityProviderStore>();
    private readonly IVerifiedIdentifierResolver _resolver = Substitute.For<IVerifiedIdentifierResolver>();
    private readonly EntraIdVerifiedIdentifierEnrollmentService _service;

    public EntraIdVerifiedIdentifierEnrollmentServiceTests()
    {
        _resolver.StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>())
            .Returns(OctoObjectId.GenerateNewId());
        _service = new EntraIdVerifiedIdentifierEnrollmentService(_providerStore, _resolver,
            Substitute.For<ILogger<EntraIdVerifiedIdentifierEnrollmentService>>());
    }

    private static RtUser User() => new() { RtId = OctoObjectId.GenerateNewId(), UserName = "alice" };

    private void ProviderIsEntraId(string name)
        => _providerStore.GetByNameAsync(name).Returns(new RtAzureEntraIdIdentityProvider { Name = name });

    [Fact]
    public async Task Enrolls_the_oid_binding_on_an_EntraID_login()
    {
        ProviderIsEntraId("MyEntra");
        var user = User();
        var claims = new List<Claim> { new(EntraObjectIdClaimUri, Oid) };

        await _service.EnrollFromExternalLoginAsync(user, "MyEntra", claims);

        await _resolver.Received(1).StoreBindingAsync(Arg.Is<VerifiedIdentifierBinding>(b =>
            b.IdentifierKind == RtIdentifierKindEnum.EntraIdObjectId &&
            b.IdentifierValue == Oid &&
            b.UserRtId == user.RtId &&
            b.EnrollmentTrust == RtTrustLevelEnum.Strong &&
            b.Source == RtIdentifierSourceEnum.IdentityProvider));
    }

    [Fact]
    public async Task Accepts_the_short_oid_claim_type()
    {
        ProviderIsEntraId("MyEntra");
        var claims = new List<Claim> { new("oid", Oid) };

        await _service.EnrollFromExternalLoginAsync(User(), "MyEntra", claims);

        await _resolver.Received(1).StoreBindingAsync(Arg.Is<VerifiedIdentifierBinding>(b =>
            b.IdentifierValue == Oid));
    }

    [Fact]
    public async Task Normalizes_a_scheme_prefixed_provider_name()
    {
        ProviderIsEntraId("MyEntra");
        var claims = new List<Claim> { new(EntraObjectIdClaimUri, Oid) };

        await _service.EnrollFromExternalLoginAsync(User(), "octosystem:MyEntra", claims);

        await _providerStore.Received(1).GetByNameAsync("MyEntra");
        await _resolver.Received(1).StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Is_a_no_op_for_a_non_EntraID_provider()
    {
        _providerStore.GetByNameAsync("Google").Returns((RtIdentityProvider?)null);
        var claims = new List<Claim> { new(EntraObjectIdClaimUri, Oid) };

        await _service.EnrollFromExternalLoginAsync(User(), "Google", claims);

        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Is_a_no_op_when_the_token_carries_no_oid()
    {
        ProviderIsEntraId("MyEntra");
        var claims = new List<Claim> { new(ClaimTypes.Email, "alice@example.com") };

        await _service.EnrollFromExternalLoginAsync(User(), "MyEntra", claims);

        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Never_throws_when_the_directory_write_fails()
    {
        ProviderIsEntraId("MyEntra");
        _resolver.StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>())
            .Returns<OctoObjectId>(_ => throw new InvalidOperationException("directory down"));
        var claims = new List<Claim> { new(EntraObjectIdClaimUri, Oid) };

        var act = async () => await _service.EnrollFromExternalLoginAsync(User(), "MyEntra", claims);

        await act.Should().NotThrowAsync();
    }
}
