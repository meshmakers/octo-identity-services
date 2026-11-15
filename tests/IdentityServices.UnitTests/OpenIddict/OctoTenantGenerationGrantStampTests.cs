using System.Security.Claims;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.TenantLifecycle;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace IdentityServices.UnitTests.OpenIddict;

/// <summary>
///     AB#9017: refresh tokens, authorization codes and device codes store the generation read at issuance as the private
///     claim <see cref="OctoClaimTypes.GrantTenantGeneration" /> (no destination), so the token endpoint can refuse a grant
///     of an earlier tenant with the same id on redemption.
/// </summary>
public class OctoTenantGenerationGrantStampTests
{
    private const string TenantId = "scratch-9017";
    private static readonly DateTime Created = new(2026, 11, 15, 13, 46, 21, 540, DateTimeKind.Utc);
    private const string CreatedMilliseconds = "1794750381540";

    private readonly ITenantLifecycleStore _store = Substitute.For<ITenantLifecycleStore>();

    [Fact]
    public void TheGrantStamps_SitRightAfterTheirPrincipalIsPrepared_WithTheirFilters()
    {
        var code = OctoTenantGenerationClaimHandler.StampAuthorizationCode.Descriptor;
        var refresh = OctoTenantGenerationClaimHandler.StampRefreshToken.Descriptor;
        var device = OctoTenantGenerationClaimHandler.StampDeviceCode.Descriptor;

        code.Order.Should().Be(OpenIddictServerHandlers.PrepareAuthorizationCodePrincipal.Descriptor.Order + 1);
        code.Order.Should().BeLessThan(OpenIddictServerHandlers.GenerateAuthorizationCode.Descriptor.Order);
        code.FilterTypes.Should().Equal(typeof(OpenIddictServerHandlerFilters.RequireAuthorizationCodeGenerated));

        refresh.Order.Should().Be(OpenIddictServerHandlers.PrepareRefreshTokenPrincipal.Descriptor.Order + 1);
        refresh.Order.Should().BeLessThan(OpenIddictServerHandlers.GenerateRefreshToken.Descriptor.Order);
        refresh.FilterTypes.Should().Equal(typeof(OpenIddictServerHandlerFilters.RequireRefreshTokenGenerated));

        device.Order.Should().Be(OpenIddictServerHandlers.PrepareDeviceCodePrincipal.Descriptor.Order + 1);
        device.Order.Should().BeLessThan(OpenIddictServerHandlers.GenerateDeviceCode.Descriptor.Order);
        device.FilterTypes.Should().Equal(typeof(OpenIddictServerHandlerFilters.RequireDeviceCodeGenerated));

        OctoTenantGenerationClaimHandler.Descriptors.Should().Contain([code, refresh, device]);
    }

    [Fact]
    public async Task AuthorizationCode_StoresTheGeneration_AsAPrivateClaim()
    {
        ArrangeRecord(Created);
        var context = CreateContext(OpenIddictServerEndpointType.Authorization);
        context.AuthorizationCodePrincipal = CreatePrincipal(TenantId);

        await new OctoTenantGenerationClaimHandler.StampAuthorizationCode(_store,
            NullLogger<OctoTenantGenerationClaimHandler.StampAuthorizationCode>.Instance).HandleAsync(context);

        var claim = context.AuthorizationCodePrincipal.FindAll(OctoClaimTypes.GrantTenantGeneration).Should().ContainSingle()
            .Subject;
        claim.Value.Should().Be(CreatedMilliseconds);
        claim.GetDestinations().Should().BeEmpty("the value stays inside the stored grant");
        context.AuthorizationCodePrincipal.FindAll(OctoClaimTypes.TenantGeneration).Should().BeEmpty();
    }

    [Fact]
    public async Task RefreshToken_ReusesTheLookupOfTheTokenRequest_WithoutASecondRead()
    {
        ArrangeRecord(Created);
        var context = CreateContext(OpenIddictServerEndpointType.Token);
        context.Principal = CreatePrincipal(TenantId);
        context.RefreshTokenPrincipal = CreatePrincipal(TenantId);

        await new OctoTenantGenerationClaimHandler.Lookup(_store,
            NullLogger<OctoTenantGenerationClaimHandler.Lookup>.Instance).HandleAsync(context);
        await new OctoTenantGenerationClaimHandler.StampRefreshToken(_store,
            NullLogger<OctoTenantGenerationClaimHandler.StampRefreshToken>.Instance).HandleAsync(context);

        context.RefreshTokenPrincipal.FindFirst(OctoClaimTypes.GrantTenantGeneration)!.Value.Should()
            .Be(CreatedMilliseconds);
        await _store.Received(1).GetAsync(TenantId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DeviceCode_WithTheUsersTenant_IsStamped_WithoutTenant_IsNot()
    {
        ArrangeRecord(Created);
        var withTenant = CreateContext(OpenIddictServerEndpointType.EndUserVerification);
        withTenant.DeviceCodePrincipal = CreatePrincipal(TenantId);
        var withoutTenant = CreateContext(OpenIddictServerEndpointType.DeviceAuthorization);
        withoutTenant.DeviceCodePrincipal = CreatePrincipal(null);
        var handler = new OctoTenantGenerationClaimHandler.StampDeviceCode(_store,
            NullLogger<OctoTenantGenerationClaimHandler.StampDeviceCode>.Instance);

        await handler.HandleAsync(withTenant);
        await handler.HandleAsync(withoutTenant);

        withTenant.DeviceCodePrincipal.FindFirst(OctoClaimTypes.GrantTenantGeneration)!.Value.Should()
            .Be(CreatedMilliseconds);
        withoutTenant.DeviceCodePrincipal.FindAll(OctoClaimTypes.GrantTenantGeneration).Should().BeEmpty();
    }

    [Fact]
    public async Task ACopiedValue_IsReplacedByTheValueReadForThisIssuance()
    {
        ArrangeRecord(Created);
        var context = CreateContext(OpenIddictServerEndpointType.Authorization);
        var principal = CreatePrincipal(TenantId);
        ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(OctoClaimTypes.GrantTenantGeneration, "1"));
        context.AuthorizationCodePrincipal = principal;

        await new OctoTenantGenerationClaimHandler.StampAuthorizationCode(_store,
            NullLogger<OctoTenantGenerationClaimHandler.StampAuthorizationCode>.Instance).HandleAsync(context);

        principal.FindAll(OctoClaimTypes.GrantTenantGeneration).Select(c => c.Value).Should()
            .Equal(CreatedMilliseconds);
    }

    [Fact]
    public async Task NoGeneration_NoClaim()
    {
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>()).Returns((TenantLifecycleRecord?)null);
        var context = CreateContext(OpenIddictServerEndpointType.Token);
        context.RefreshTokenPrincipal = CreatePrincipal(TenantId);

        await new OctoTenantGenerationClaimHandler.StampRefreshToken(_store,
            NullLogger<OctoTenantGenerationClaimHandler.StampRefreshToken>.Instance).HandleAsync(context);

        context.RefreshTokenPrincipal.FindAll(OctoClaimTypes.GrantTenantGeneration).Should().BeEmpty();
        context.IsRejected.Should().BeFalse();
    }

    [Fact]
    public async Task StoreFailure_RefusesTheIssuanceWithServerError()
    {
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>()).ThrowsAsync(new TimeoutException("down"));
        var context = CreateContext(OpenIddictServerEndpointType.Authorization);
        context.AuthorizationCodePrincipal = CreatePrincipal(TenantId);

        await new OctoTenantGenerationClaimHandler.StampAuthorizationCode(_store,
            NullLogger<OctoTenantGenerationClaimHandler.StampAuthorizationCode>.Instance).HandleAsync(context);

        context.IsRejected.Should().BeTrue();
        context.Error.Should().Be(Errors.ServerError);
        context.AuthorizationCodePrincipal.FindAll(OctoClaimTypes.GrantTenantGeneration).Should().BeEmpty();
    }

    [Fact]
    public async Task ACarriedMismatch_IsKeptOnTheRotatedRefreshToken_InsteadOfTheCurrentGeneration()
    {
        ArrangeRecord(Created);
        var context = CreateContext(OpenIddictServerEndpointType.Token);
        context.RefreshTokenPrincipal = CreatePrincipal(TenantId);
        context.Transaction.Properties[OctoTenantGenerationClaimHandler.CarriedGrantGenerationPropertyName] =
            new OctoTenantGenerationClaimHandler.CarriedGrantGeneration(TenantId, "1763193600123");

        await new OctoTenantGenerationClaimHandler.StampRefreshToken(_store,
            NullLogger<OctoTenantGenerationClaimHandler.StampRefreshToken>.Instance).HandleAsync(context);

        context.RefreshTokenPrincipal.FindAll(OctoClaimTypes.GrantTenantGeneration).Select(c => c.Value).Should()
            .Equal(["1763193600123"], "LogOnly must not launder an old grant into a valid one");
    }

    [Fact]
    public void ThePrivateClaim_HasNoDestination_EvenForClientsWithUserClaimsInTheIdToken()
    {
        var claim = new Claim(OctoClaimTypes.GrantTenantGeneration, CreatedMilliseconds);

        OctoClaimsDestinations.Resolve(claim).Should().BeEmpty();
        OctoClaimsDestinations.ForClient(true)(claim).Should().BeEmpty();
    }

    private void ArrangeRecord(DateTime createdUtc) =>
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleRecord { TenantId = TenantId, CreatedUtc = createdUtc });

    private static ProcessSignInContext CreateContext(OpenIddictServerEndpointType endpoint)
    {
        var transaction = new OpenIddictServerTransaction
        {
            Request = new OpenIddictRequest { GrantType = GrantTypes.RefreshToken },
            EndpointType = endpoint,
            CancellationToken = TestContext.Current.CancellationToken
        };
        return new ProcessSignInContext(transaction);
    }

    private static ClaimsPrincipal CreatePrincipal(string? tenantId)
    {
        var identity = new ClaimsIdentity("test", Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, "subject-9017"));
        if (tenantId != null)
        {
            identity.AddClaim(new Claim(OctoClaimTypes.TenantId, tenantId));
        }

        return new ClaimsPrincipal(identity);
    }
}
