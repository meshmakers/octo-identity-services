using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Claim destination policy for OpenIddict-issued tokens (AB#4990). OpenIddict emits only
///     <c>sub</c> by default — every other claim needs an explicit destination. This mapping
///     reproduces the Duende token shapes pinned by the golden baseline
///     (<c>tests/IdentityServices.IntegrationTests/GoldenFiles</c>):
///     <list type="bullet">
///         <item>Authorization/session claims (<c>amr</c>, <c>idp</c>, <c>auth_time</c>,
///             <c>sid</c>) go into access AND identity tokens.</item>
///         <item>Octo claims (<c>tenant_id</c>, <c>allowed_tenants</c>, <c>home_tenant_id</c>)
///             and <c>role</c> go into access tokens only.</item>
///         <item>Profile claims (name, email, …) go into NO token — the userinfo endpoint
///             serves them fresh, exactly like Duende did.</item>
///     </list>
/// </summary>
public static class OctoClaimsDestinations
{
    /// <summary>Destination selector for <c>ClaimsPrincipal.SetDestinations</c>.</summary>
    public static IEnumerable<string> Resolve(Claim claim)
    {
        switch (claim.Type)
        {
            case Claims.Subject:
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                break;

            case Claims.AuthenticationMethodReference:
            case "idp":
            case Claims.AuthenticationTime:
            case "sid":
                yield return Destinations.AccessToken;
                yield return Destinations.IdentityToken;
                break;

            case Claims.Role:
            case OctoClaimTypes.TenantId:
            case OctoClaimTypes.AllowedTenants:
            case OctoClaimTypes.HomeTenantId:
                yield return Destinations.AccessToken;
                break;

            // Everything else (profile claims etc.) is intentionally not destined into
            // tokens; the userinfo endpoint serves it (Duende parity).
        }
    }
}
