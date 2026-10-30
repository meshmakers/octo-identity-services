using System.Security.Claims;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>AB#7914: the caller of a REST role change comes from the validated token claims only.</summary>
public class RoleChangeCallerTests
{
    [Fact]
    public void UserToken_HasSubject_AndRolesFromBothClaimSpellings()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "u1"), new Claim("role", "UserManagement"), new Claim(ClaimTypes.Role, "usermanagement"),
            new Claim("role", "Development")
        ], "Bearer"));

        var caller = RoleChangeCaller.FromPrincipal(principal);

        caller.Subject.Should().Be("u1");
        caller.ClientId.Should().BeNull();
        caller.Roles.Should().BeEquivalentTo("UserManagement", "Development");
    }

    [Fact]
    public void ClientCredentialsToken_HasNoSubject_SoItIsNeverSelf()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("client_id", "svc"), new Claim("role", "UserManagement")], "Bearer"));

        var caller = RoleChangeCaller.FromPrincipal(principal);

        caller.Subject.Should().BeNull();
        caller.ClientId.Should().Be("svc");
    }

    [Theory]
    [InlineData(RoleChangeReasons.SelfGrant, "own user")]
    [InlineData(RoleChangeReasons.LastAdministrator, "without a user administrator")]
    public void Title_IsAReadableSentence(string reason, string fragment) =>
        new RoleChangeDecision(reason, []).Title.Should().Contain(fragment);

    [Fact]
    public void Title_OfRoleNotHeld_NamesTheRoles() =>
        new RoleChangeDecision(RoleChangeReasons.RoleNotHeld, ["SecretManagement", "Development"]).Title
            .Should().Contain("SecretManagement, Development");
}
