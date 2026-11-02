using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5708 — the <c>home_tenant_id</c> claim of a cross-tenant shadow user is the nearest source
///     tenant of its <c>xt_{tenant}_{user}</c> name, split against the tenant registry. Tenant ids may
///     contain '_', so the first separator is not the end of the tenant id; an ambiguous or
///     unregistered prefix omits the claim (consumers fall back to <c>tenant_id</c>).
/// </summary>
public class ShadowUserHomeTenantClaimTests
{
    private const string LoginTenantId = "child";

    private readonly RegisteredTenantsShadowUserChainResolver _registry =
        new(LoginTenantId, "meshmakers", "karlplus", "home_tenant");

    private readonly OctoTokenClaimsService _sut;

    public ShadowUserHomeTenantClaimTests()
    {
        var userManager = Substitute.For<UserManager<RtUser>>(
            Substitute.For<IUserStore<RtUser>>(),
            Substitute.For<Microsoft.Extensions.Options.IOptions<IdentityOptions>>(),
            Substitute.For<IPasswordHasher<RtUser>>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            Substitute.For<ILookupNormalizer>(),
            Substitute.For<IdentityErrorDescriber>(),
            Substitute.For<IServiceProvider>(),
            Substitute.For<ILogger<UserManager<RtUser>>>());
        userManager.GetRolesAsync(Arg.Any<RtUser>()).Returns(new List<string>());

        var allowedTenantsResolver = Substitute.For<IAllowedTenantsResolver>();
        allowedTenantsResolver.ResolveAsync(Arg.Any<string>(), Arg.Any<RtUser>())
            .Returns(new List<string> { LoginTenantId });

        _sut = new OctoTokenClaimsService(
            userManager,
            allowedTenantsResolver,
            _registry,
            Substitute.For<IClientRoleStore>(),
            Substitute.For<IOctoResourceStore>());
    }

    private async Task<string?> HomeTenantClaimOfAsync(string userName)
    {
        var identity = new ClaimsIdentity("test");
        var user = new RtUser { RtId = OctoObjectId.GenerateNewId(), UserName = userName };

        await _sut.PopulateUserClaimsAsync(identity, user, LoginTenantId);

        return identity.FindFirst(OctoClaimTypes.HomeTenantId)?.Value;
    }

    [Fact]
    public async Task ShadowUser_CarriesItsSourceTenant()
        => (await HomeTenantClaimOfAsync("xt_meshmakers_gerald")).Should().Be("meshmakers");

    [Fact]
    public async Task NestedShadowUser_CarriesTheNearestSourceTenant()
        => (await HomeTenantClaimOfAsync("xt_karlplus_xt_meshmakers_gerald")).Should().Be("karlplus");

    [Fact]
    public async Task ShadowUserOfAnUnderscoreTenant_CarriesTheFullTenantId()
        => (await HomeTenantClaimOfAsync("xt_home_tenant_admin")).Should().Be("home_tenant",
            "the first-separator split used to stamp the non-existent tenant 'home'");

    [Fact]
    public async Task AmbiguousShadowName_OmitsTheClaim()
    {
        // "acme" and "acme_corp" both exist: xt_acme_corp_boss is boss@acme_corp or corp_boss@acme.
        _registry.Register("acme", "acme_corp");

        (await HomeTenantClaimOfAsync("xt_acme_corp_boss")).Should().BeNull();
    }

    [Fact]
    public async Task UnregisteredSourceTenant_OmitsTheClaim()
        => (await HomeTenantClaimOfAsync("xt_gone_admin")).Should().BeNull();

    [Fact]
    public async Task LocalUser_HasNoHomeTenantClaim()
        => (await HomeTenantClaimOfAsync("meshmakers_gerald")).Should().BeNull();
}
