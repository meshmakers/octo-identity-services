using System.Security.Claims;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#7958: the caller of an audited action is read from the raw access token claims (the identity service keeps
///     <c>MapInboundClaims = false</c>), not from <c>User.Identity.Name</c> alone.
/// </summary>
public class AuditActorTests
{
    [Fact]
    public void CliUserToken_SubAndPreferredUsernameWithoutMappedName_AreRecorded()
    {
        var principal = Principal(
            ("sub", "6a1f0c2b9d4e8f7a6b5c4d3e"), ("preferred_username", "gerald"), ("email", "g@example.com"),
            ("client_id", "octo-cli"), ("tenant_id", "octosystem"), ("jti", "token-id"));

        principal.Identity!.Name.Should().BeNull("no claim maps to Identity.Name — the cause of '(unknown)'");
        var actor = AuditActor.FromPrincipal(principal);

        actor.Should().Be(new AuditActor("6a1f0c2b9d4e8f7a6b5c4d3e", "gerald", "octo-cli", "octosystem"));
        actor.Actor.Should().Be("gerald");
    }

    [Fact]
    public void UserName_FallsBackToName_ThenToTheIdentityName()
    {
        AuditActor.FromPrincipal(Principal(("sub", "s1"), ("name", "Gerald L"))).UserName.Should().Be("Gerald L");

        var mapped = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "s1"), new Claim(ClaimTypes.Name, "mapped-name")], "Bearer"));
        AuditActor.FromPrincipal(mapped).UserName.Should().Be("mapped-name");
    }

    [Fact]
    public void ClientCredentialsToken_RecordsTheClientIdAsActor()
    {
        // The token endpoint sets sub = client id for client credentials; there is no user name.
        var actor = AuditActor.FromPrincipal(Principal(("sub", "svc-client"), ("client_id", "svc-client"),
            ("tenant_id", "meshtest")));

        actor.UserName.Should().BeNull();
        actor.ClientId.Should().Be("svc-client");
        actor.Actor.Should().Be("client svc-client");
    }

    [Fact]
    public void AuthorizedParty_IsUsedWhenClientIdIsMissing()
        => AuditActor.FromPrincipal(Principal(("sub", "s1"), ("azp", "spa"))).ClientId.Should().Be("spa");

    [Fact]
    public void SubjectOnly_IsTheActor_UnknownOnlyWithoutAnyClaim()
    {
        AuditActor.FromPrincipal(Principal(("sub", "s1"))).Actor.Should().Be("s1");

        var empty = AuditActor.FromPrincipal(new ClaimsPrincipal(new ClaimsIdentity()));
        empty.Actor.Should().Be("(unknown)");
        empty.SubjectOrNone.Should().Be("-");
        empty.ClientIdOrNone.Should().Be("-");
        empty.TenantIdOrNone.Should().Be("-");
        AuditActor.FromPrincipal(null).Should().Be(AuditActor.Anonymous);
    }

    [Fact]
    public void BlankClaims_CountAsAbsent()
        => AuditActor.FromPrincipal(Principal(("sub", " "), ("preferred_username", ""), ("client_id", "c")))
            .Should().Be(new AuditActor(null, null, "c", null));

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims)
        => new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), "Bearer"));
}
