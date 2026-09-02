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
///             and <c>role</c> go into access tokens — and ALSO into the identity token when the
///             client sets <c>AlwaysIncludeUserClaimsInIdToken</c> (Duende parity: the Refinery
///             Studio reads its identity, tenant and roles from the id_token).</item>
///         <item>Profile claims (name, preferred_username, email, family/given name) go into the
///             identity token only for <c>AlwaysIncludeUserClaimsInIdToken</c> clients; otherwise
///             into NO token — the userinfo endpoint serves them, exactly like Duende did.</item>
///     </list>
/// </summary>
public static class OctoClaimsDestinations
{
    /// <summary>Destination selector for clients without AlwaysIncludeUserClaimsInIdToken.</summary>
    public static IEnumerable<string> Resolve(Claim claim) => ResolveCore(claim, false);

    /// <summary>
    ///     Destination selector honoring the client's <c>AlwaysIncludeUserClaimsInIdToken</c>
    ///     setting (Duende parity — AB#4996).
    /// </summary>
    public static Func<Claim, IEnumerable<string>> ForClient(bool alwaysIncludeUserClaimsInIdToken)
        => claim => ResolveCore(claim, alwaysIncludeUserClaimsInIdToken);

    private static IEnumerable<string> ResolveCore(Claim claim, bool userClaimsInIdToken)
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
                if (userClaimsInIdToken)
                {
                    yield return Destinations.IdentityToken;
                }

                break;

            case Claims.Name:
            case Claims.PreferredUsername:
            case Claims.Email:
            case Claims.FamilyName:
            case Claims.GivenName:
                if (userClaimsInIdToken)
                {
                    yield return Destinations.IdentityToken;
                }

                // Otherwise intentionally not destined into tokens; userinfo serves them
                // (Duende parity).
                break;

            // Everything else is intentionally not destined into tokens.
        }
    }
}
