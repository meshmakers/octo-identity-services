using System.Security.Claims;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityModel;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5026 — <b>the load-bearing test of the delegation grant.</b> It pins the exact claim
///     composition of a delegated access token, end to end across the two halves that produce it.
/// </summary>
/// <remarks>
///     <para>
///         The trap this guards: <c>OnBehalfOfGrantValidator</c> issues the token for the
///         <b>user's</b> <c>sub</c>, so Duende's <c>AddAspNetIdentity&lt;RtUser&gt;</c> +
///         <c>ProfileService&lt;RtUser&gt;</c> pipeline resolves that user's <b>full</b> role set
///         from <c>OctoUserStore</c> and puts it into <c>ProfileDataRequestContext.IssuedClaims</c>,
///         exactly as for a normal login. If those survive, the role intersection never reaches the
///         token and the whole grant is a placebo that hands out the user's full authority.
///     </para>
///     <para>
///         So this test does not check the resolver's arithmetic (that is
///         <see cref="DelegatedIdentityResolverTests" />) — it checks the <b>wire result</b>: the
///         validator's real <see cref="GrantValidationResult" /> subject, fed through
///         <c>UserProfileService</c>'s real filter, over an <c>IssuedClaims</c> list populated the
///         way the base profile service populates it.
///     </para>
/// </remarks>
public class DelegationClaimCompositionTests
{
    private const string ServiceAccountClientId = "octo-pipeline-sa";
    private const string UserSubjectId = "68b0000000000000000000a1";

    [Fact]
    public void DelegatedToken_CarriesOnlyTheIntersectionRoles_NotTheUsersFullRoleSet()
    {
        // The validator resolved an intersection of exactly one role.
        var subject = DelegatedSubject("AssetReader");

        // What the base ProfileService / OctoUserStore contributes for this same user: their FULL
        // role set, plus ordinary profile claims.
        var issuedClaims = UserProfileClaims("AssetReader", "AssetWriter", "TenantAdministrator");

        var wasDelegated = UserProfileService.ApplyDelegationClaims(subject, issuedClaims);

        wasDelegated.Should().BeTrue();

        RoleValues(issuedClaims).Should().BeEquivalentTo(["AssetReader"],
            "only the intersection may become role claims");
        RoleValues(issuedClaims).Should().NotContain("TenantAdministrator",
            "THE regression: the user's full role set must never survive into a delegated token");
        RoleValues(issuedClaims).Should().NotContain("AssetWriter");
    }

    [Fact]
    public void DelegatedToken_CarriesTheActClaimNamingTheServiceAccount()
    {
        var subject = DelegatedSubject("AssetReader");
        var issuedClaims = UserProfileClaims("AssetReader");

        UserProfileService.ApplyDelegationClaims(subject, issuedClaims);

        issuedClaims.Should().ContainSingle(c => c.Type == DelegationConstants.ActClaimType)
            .Which.Value.Should().Be(ServiceAccountClientId);
    }

    [Fact]
    public void DelegatedToken_KeepsNonRoleProfileClaims()
    {
        var subject = DelegatedSubject("AssetReader");
        var issuedClaims = UserProfileClaims("AssetReader");

        UserProfileService.ApplyDelegationClaims(subject, issuedClaims);

        issuedClaims.Should().Contain(c => c.Type == JwtClaimTypes.Name && c.Value == "alice");
        issuedClaims.Should().Contain(c => c.Type == JwtClaimTypes.Email);
    }

    [Fact]
    public void DelegatedToken_NeverLeaksTheInternalDelegatedRoleClaimType()
    {
        var subject = DelegatedSubject("AssetReader");
        var issuedClaims = UserProfileClaims("AssetReader");

        UserProfileService.ApplyDelegationClaims(subject, issuedClaims);

        // The transport claim type exists only on the grant-result subject, never in the token.
        issuedClaims.Should().NotContain(c => c.Type == DelegationConstants.DelegatedRoleClaimType);
    }

    [Fact]
    public void EmptyIntersection_StripsEveryRoleClaimAndAddsNoneBack()
    {
        var subject = DelegatedSubject();
        var issuedClaims = UserProfileClaims("AssetReader", "TenantAdministrator");

        UserProfileService.ApplyDelegationClaims(subject, issuedClaims);

        RoleValues(issuedClaims).Should().BeEmpty(
            "an empty intersection must authorize nothing, so downstream role gates fail closed");
        issuedClaims.Should().Contain(c => c.Type == DelegationConstants.ActClaimType);
    }

    [Fact]
    public void NonDelegatedToken_IsLeftCompletelyUntouched()
    {
        // A normal login / token-exchange result: no act claim on the subject.
        var subject = new GrantValidationResult(UserSubjectId, "pwd").Subject;
        var issuedClaims = UserProfileClaims("AssetReader", "TenantAdministrator");

        var wasDelegated = UserProfileService.ApplyDelegationClaims(subject, issuedClaims);

        wasDelegated.Should().BeFalse();
        RoleValues(issuedClaims).Should().BeEquivalentTo("AssetReader", "TenantAdministrator");
        issuedClaims.Should().NotContain(c => c.Type == DelegationConstants.ActClaimType);
    }

    [Fact]
    public void NullSubject_IsNotTreatedAsDelegated()
    {
        var issuedClaims = UserProfileClaims("AssetReader");

        UserProfileService.ApplyDelegationClaims(null, issuedClaims).Should().BeFalse();

        RoleValues(issuedClaims).Should().BeEquivalentTo("AssetReader");
    }

    // ---------- helpers ----------

    /// <summary>
    ///     Builds the subject principal exactly as the grant validator does — via the real
    ///     <see cref="OnBehalfOfGrantValidator.BuildDelegationClaims" /> and a real
    ///     <see cref="GrantValidationResult" /> — so the claim types and shapes under test are the
    ///     ones actually produced at runtime.
    /// </summary>
    private static ClaimsPrincipal DelegatedSubject(params string[] intersectionRoles)
    {
        var claims = OnBehalfOfGrantValidator.BuildDelegationClaims(
            ServiceAccountClientId, new HashSet<string>(intersectionRoles, StringComparer.OrdinalIgnoreCase));

        return new GrantValidationResult(
            UserSubjectId, DelegationConstants.AuthenticationMethod, claims).Subject;
    }

    /// <summary>
    ///     The claims the base <c>ProfileService&lt;RtUser&gt;</c> leaves in <c>IssuedClaims</c> for
    ///     the user the delegated token runs on: their full resolved role set plus profile claims.
    /// </summary>
    private static List<Claim> UserProfileClaims(params string[] fullUserRoles)
    {
        var claims = new List<Claim>
        {
            new(JwtClaimTypes.Name, "alice"),
            new(JwtClaimTypes.Email, "alice@example.com")
        };
        claims.AddRange(fullUserRoles.Select(r => new Claim(JwtClaimTypes.Role, r)));
        return claims;
    }

    private static IEnumerable<string> RoleValues(IEnumerable<Claim> claims) =>
        claims.Where(c => c.Type == JwtClaimTypes.Role).Select(c => c.Value);
}
