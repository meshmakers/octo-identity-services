using System.Security.Claims;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5026 — <b>the load-bearing test of the delegation grant.</b> It pins the exact claim
///     composition of a delegated access token.
/// </summary>
/// <remarks>
///     <para>
///         The trap this guards: the token endpoint issues the delegated token for the
///         <b>user's</b> <c>sub</c> and populates the identity through
///         <c>IOctoTokenClaimsService.PopulateUserClaimsAsync</c>, which resolves that user's
///         <b>full</b> role set — exactly as for a normal login. If those role claims survive, the
///         role intersection never reaches the token and the whole grant is a placebo that hands
///         out the user's full authority.
///     </para>
///     <para>
///         So this test does not check the resolver's arithmetic (that is
///         <c>DelegatedIdentityResolverTests</c>) — it checks the composed identity:
///         <see cref="OnBehalfOfProcessor.ApplyDelegationClaims" /> applied over an identity
///         populated the way the token claims service populates it.
///     </para>
/// </remarks>
public class DelegationClaimCompositionTests
{
    private const string ServiceAccountClientId = "octo-pipeline-sa";

    [Fact]
    public void DelegatedToken_CarriesOnlyTheIntersectionRoles_NotTheUsersFullRoleSet()
    {
        // What the token claims service contributes for the user: their FULL role set plus
        // ordinary profile claims. The resolver's intersection is exactly one role.
        var identity = UserIdentity("AssetReader", "AssetWriter", "TenantAdministrator");

        OnBehalfOfProcessor.ApplyDelegationClaims(identity, ServiceAccountClientId,
            Intersection("AssetReader"));

        RoleValues(identity).Should().BeEquivalentTo(["AssetReader"],
            "only the intersection may become role claims");
        RoleValues(identity).Should().NotContain("TenantAdministrator",
            "THE regression: the user's full role set must never survive into a delegated token");
        RoleValues(identity).Should().NotContain("AssetWriter");
    }

    [Fact]
    public void DelegatedToken_CarriesTheActClaimNamingTheServiceAccount()
    {
        var identity = UserIdentity("AssetReader");

        OnBehalfOfProcessor.ApplyDelegationClaims(identity, ServiceAccountClientId,
            Intersection("AssetReader"));

        identity.Claims.Should().ContainSingle(c => c.Type == DelegationConstants.ActClaimType)
            .Which.Value.Should().Be(ServiceAccountClientId);
    }

    [Fact]
    public void DelegatedToken_KeepsNonRoleProfileClaims()
    {
        var identity = UserIdentity("AssetReader");

        OnBehalfOfProcessor.ApplyDelegationClaims(identity, ServiceAccountClientId,
            Intersection("AssetReader"));

        identity.Claims.Should().Contain(c => c.Type == Claims.Name && c.Value == "alice");
        identity.Claims.Should().Contain(c => c.Type == Claims.Email);
    }

    [Fact]
    public void EmptyIntersection_StripsEveryRoleClaimAndAddsNoneBack()
    {
        var identity = UserIdentity("AssetReader", "TenantAdministrator");

        OnBehalfOfProcessor.ApplyDelegationClaims(identity, ServiceAccountClientId, Intersection());

        RoleValues(identity).Should().BeEmpty(
            "an empty intersection must authorize nothing, so downstream role gates fail closed");
        identity.Claims.Should().Contain(c => c.Type == DelegationConstants.ActClaimType);
    }

    // ---------- helpers ----------

    /// <summary>
    ///     An identity populated the way <c>PopulateUserClaimsAsync</c> populates it for the user
    ///     the delegated token runs on: their full resolved role set plus profile claims.
    /// </summary>
    private static ClaimsIdentity UserIdentity(params string[] fullUserRoles)
    {
        var identity = new ClaimsIdentity("test", Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Name, "alice"));
        identity.AddClaim(new Claim(Claims.Email, "alice@example.com"));
        foreach (var role in fullUserRoles)
        {
            identity.AddClaim(new Claim(Claims.Role, role));
        }

        return identity;
    }

    private static IReadOnlySet<string> Intersection(params string[] roles) =>
        new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);

    private static IEnumerable<string> RoleValues(ClaimsIdentity identity) =>
        identity.Claims.Where(c => c.Type == Claims.Role).Select(c => c.Value);
}
