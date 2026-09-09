using System.Security.Claims;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5114 — pins the claim composition of an impersonated access token: the TARGET's roles in
///     the same claim shape a genuine <c>client_credentials</c> token carries, plus <c>act</c>
///     naming the ACTOR — the actor's only trace on the token.
/// </summary>
/// <remarks>
///     The counterpart of <see cref="DelegationClaimCompositionTests" /> for the impersonation
///     grant. The <c>sub</c>/<c>client_id</c> re-stamping is the <c>OctoAccessTokenShapeHandler</c>'s
///     job at token generation and is not visible on the <see cref="ClaimsIdentity" /> composed
///     here.
/// </remarks>
public class ImpersonationClaimCompositionTests
{
    private const string ActorClientId = "adapter-chart-client";

    [Fact]
    public void ImpersonatedToken_CarriesTheTargetsRoles()
    {
        var identity = NewIdentity();

        ImpersonationProcessor.ApplyImpersonationClaims(identity, ActorClientId,
            Roles("CommunicationManagement", "AssetReader"));

        identity.Claims.Where(c => c.Type == Claims.Role).Select(c => c.Value)
            .Should().BeEquivalentTo("CommunicationManagement", "AssetReader");
    }

    /// <summary>
    ///     act must name the ACTOR — for delegation it names the SA, here the caller IS becoming
    ///     the SA, so the audit-relevant "who really called" is the actor.
    /// </summary>
    [Fact]
    public void ImpersonatedToken_CarriesTheActClaimNamingTheActor()
    {
        var identity = NewIdentity();

        ImpersonationProcessor.ApplyImpersonationClaims(identity, ActorClientId, Roles("AssetReader"));

        identity.Claims.Should().ContainSingle(c => c.Type == ImpersonationConstants.ActClaimType)
            .Which.Value.Should().Be(ActorClientId);
    }

    /// <summary>
    ///     The act claim type is deliberately THE SAME claim as the delegation grant's — consumers
    ///     read one claim to learn who really called, regardless of the minting grant.
    /// </summary>
    [Fact]
    public void ActClaimType_IsSharedWithTheDelegationGrant()
    {
        ImpersonationConstants.ActClaimType.Should().Be(DelegationConstants.ActClaimType);
    }

    /// <summary>A target without roles yields a token that authorizes nothing — but still an act claim.</summary>
    [Fact]
    public void TargetWithoutRoles_YieldsNoRoleClaims()
    {
        var identity = NewIdentity();

        ImpersonationProcessor.ApplyImpersonationClaims(identity, ActorClientId, Roles());

        identity.Claims.Should().NotContain(c => c.Type == Claims.Role);
        identity.Claims.Should().ContainSingle(c => c.Type == ImpersonationConstants.ActClaimType);
    }

    // ---------- helpers ----------

    private static ClaimsIdentity NewIdentity() => new("test", Claims.Name, Claims.Role);

    private static IReadOnlySet<string> Roles(params string[] roles) =>
        new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);
}
