using System.Security.Claims;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Builds the token claims for OpenIddict-issued principals with exact parity to the claims
///     the pre-migration <c>UserProfileService</c> and <c>ClientCredentialsRoleTokenValidator</c>
///     produced (AB#4990). The golden baseline in
///     <c>tests/IdentityServices.IntegrationTests/GoldenFiles</c> pins the resulting token shapes:
///     <list type="bullet">
///         <item>User access tokens: <c>sub</c>, <c>tenant_id</c>, <c>allowed_tenants</c> (multi),
///             <c>home_tenant_id</c> (cross-tenant shadow users), effective <c>role</c> claims.</item>
///         <item><c>client_credentials</c> access tokens: unprefixed effective <c>role</c> claims
///             resolved from the client's AssignedRole associations + group memberships (AB#4183);
///             no tenant/session claims.</item>
///         <item><c>aud</c>: the API resources whose scopes were granted — resource-service
///             JwtBearer validation depends on these exact audience values.</item>
///         <item>Profile claims (name, email, family/given name) are NOT destined into tokens —
///             they are served by the userinfo endpoint.</item>
///     </list>
/// </summary>
public interface IOctoTokenClaimsService
{
    /// <summary>
    ///     Adds the Octo user token claims (subject, roles, tenant claims) to
    ///     <paramref name="identity" />. Session claims (<c>amr</c>, <c>idp</c>, <c>auth_time</c>,
    ///     <c>sid</c>) are the caller's responsibility — they originate from the cookie ticket.
    /// </summary>
    Task PopulateUserClaimsAsync(ClaimsIdentity identity, RtUser user, string loginTenantId);

    /// <summary>
    ///     Adds the effective role claims of a machine-to-machine client to
    ///     <paramref name="identity" /> (unprefixed, same shape as user tokens — AB#4183).
    /// </summary>
    Task PopulateClientClaimsAsync(ClaimsIdentity identity, RtClient client);

    /// <summary>
    ///     Resolves the <c>aud</c> values for the granted scopes: the names of all enabled API
    ///     resources that carry at least one of the scopes.
    /// </summary>
    Task<IReadOnlyCollection<string>> ResolveAudiencesAsync(IEnumerable<string> scopes);
}

internal class OctoTokenClaimsService(
    UserManager<RtUser> userManager,
    IAllowedTenantsResolver allowedTenantsResolver,
    IClientRoleStore clientRoleStore,
    IOctoResourceStore resourceStore) : IOctoTokenClaimsService
{
    public async Task PopulateUserClaimsAsync(ClaimsIdentity identity, RtUser user, string loginTenantId)
    {
        identity.SetClaim(Claims.Subject, user.RtId.ToString());

        // Profile claims. Destinations decide per client whether
        // they reach the id_token (AlwaysIncludeUserClaimsInIdToken) — they never enter access
        // tokens (golden-pinned).
        if (!string.IsNullOrEmpty(user.UserName))
        {
            identity.SetClaim(Claims.Name, user.UserName);
            identity.SetClaim(Claims.PreferredUsername, user.UserName);
        }

        if (!string.IsNullOrEmpty(user.Email))
        {
            identity.SetClaim(Claims.Email, user.Email);
        }

        if (!string.IsNullOrEmpty(user.LastName))
        {
            identity.SetClaim(Claims.FamilyName, user.LastName);
        }

        if (!string.IsNullOrEmpty(user.FirstName))
        {
            identity.SetClaim(Claims.GivenName, user.FirstName);
        }

        foreach (var roleName in await userManager.GetRolesAsync(user))
        {
            identity.AddClaim(new Claim(Claims.Role, roleName));
        }

        if (!string.IsNullOrEmpty(loginTenantId))
        {
            // The SPA detects tenant mismatch via tenant_id; backend middleware authorizes the
            // route tenant against allowed_tenants (octo-common-services).
            identity.SetClaim(OctoClaimTypes.TenantId, loginTenantId);

            foreach (var tenantId in await allowedTenantsResolver.ResolveAsync(loginTenantId, user))
            {
                identity.AddClaim(new Claim(OctoClaimTypes.AllowedTenants, tenantId));
            }
        }

        // Cross-tenant shadow users (xt_{homeTenant}_{userName}) carry their home tenant so
        // consumers can resolve the originating identity.
        if (user.UserName != null && user.UserName.StartsWith("xt_"))
        {
            var parts = user.UserName.Split('_', 3);
            if (parts.Length >= 3)
            {
                identity.SetClaim(OctoClaimTypes.HomeTenantId, parts[1]);
            }
        }
    }

    public async Task PopulateClientClaimsAsync(ClaimsIdentity identity, RtClient client)
    {
        foreach (var roleName in await clientRoleStore.GetEffectiveRoleNamesAsync(client.RtId))
        {
            identity.AddClaim(new Claim(Claims.Role, roleName));
        }
    }

    public async Task<IReadOnlyCollection<string>> ResolveAudiencesAsync(IEnumerable<string> scopes)
    {
        var scopeNames = scopes.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct().ToList();
        if (scopeNames.Count == 0)
        {
            return [];
        }

        var apiResources = await resourceStore.FindRtApiResourcesByScopeNameAsync(scopeNames);
        return apiResources
            .Where(r => r.Enabled)
            .Select(r => r.Name)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }
}

/// <summary>Octo-specific claim type names (wire-contract, do not change).</summary>
public static class OctoClaimTypes
{
    public const string TenantId = "tenant_id";
    public const string AllowedTenants = "allowed_tenants";
    public const string HomeTenantId = "home_tenant_id";
}
