using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>AB#7859 — the session claims survive the security-stamp revalidation, nothing else is added.</summary>
public class SessionClaimPreservationTests
{
    [Fact]
    public void Preserve_CopiesAmrIdpAndSid_FromTheVerifiedPrincipal()
    {
        var current = Principal(("sub", "u1"), ("amr", "pwd"), ("amr", "mfa"), ("idp", "local"), ("sid", "s-1"));
        var refreshed = Principal(("sub", "u1"), ("role", "Admin"));

        SessionClaimPreservation.Preserve(current, refreshed);

        refreshed.FindAll("amr").Select(c => c.Value).Should().BeEquivalentTo(["pwd", "mfa"]);
        refreshed.FindFirst("idp")!.Value.Should().Be("local");
        refreshed.FindFirst("sid")!.Value.Should().Be("s-1");
        refreshed.FindAll("role").Should().ContainSingle("user claims come from the rebuilt principal only");
    }

    [Fact]
    public void Preserve_DoesNotDuplicate_AndCopiesNoOtherClaimType()
    {
        var current = Principal(("amr", "mfa"), ("role", "Stale"), ("tenant_id", "old"));
        var refreshed = Principal(("amr", "mfa"));

        SessionClaimPreservation.Preserve(current, refreshed);

        refreshed.FindAll("amr").Should().ContainSingle();
        refreshed.HasClaim(c => c.Type is "role" or "tenant_id").Should().BeFalse(
            "only the claims that describe the sign-in are carried over; roles are re-resolved");
    }

    [Fact]
    public void Preserve_WithoutCurrentPrincipal_ChangesNothing()
    {
        var refreshed = Principal(("sub", "u1"));

        SessionClaimPreservation.Preserve(null, refreshed);

        refreshed.Claims.Should().ContainSingle();
    }

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims)
        => new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), "Identity.Application"));
}
