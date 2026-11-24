using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.RoleGrants;

/// <summary>Marker of <see cref="AiBudgetAdminGrant"/> in the system tenant's configuration.</summary>
public sealed class AiBudgetAdminGrantMarker : AdministratorRoleGrantMarker;

/// <summary>
///     AB#8690: one-time, additive grant of the platform role <c>AiBudgetAdmin</c> (blueprint 1.11.0, 660…63) to the
///     existing HUMAN administrators of the SYSTEM tenant — local users holding both <c>AdminPanelManagement</c> and
///     <c>TenantManagement</c>, as for <c>SecretManagement</c> (<see cref="AdministratorRoleOneTimeGrant"/>).
/// </summary>
/// <remarks>
///     <para>
///         Why: the role-change guard lets only a holder of a platform role grant it, and the seed gives
///         <c>AiBudgetAdmin</c> to nobody (not TenantOwners, not the initial administrator). Without this step nobody
///         could ever hold it. After it, a holder grants it to further people with <c>AddUserToRole</c>; the guard
///         stays unchanged.
///     </para>
///     <para>
///         Never in a child tenant (the AI service refuses the role from a child-tenant token anyway), never to a
///         group, a client or a cross-tenant shadow user. Runs once (marker
///         <see cref="IdentityServiceConstants.AiBudgetAdminGrantKey"/>): an operator who removes the role later does
///         not see it come back. A run that finds no administrator (fresh installation: the system tenant is set up
///         before its first administrator exists) writes no marker, so the first setup after the administrator exists
///         grants it.
///     </para>
/// </remarks>
internal static class AiBudgetAdminGrant
{
    public static async Task<AdministratorRoleGrantResult> EnsureAsync(
        ITenantContext tenantContext, string systemTenantId, ILogger logger)
    {
        if (!string.Equals(tenantContext.TenantId, systemTenantId, StringComparison.OrdinalIgnoreCase))
        {
            // Child tenants never get it, and no marker is written there.
            return new AdministratorRoleGrantResult(AdministratorRoleGrantStatus.NotApplicable, []);
        }

        return await AdministratorRoleOneTimeGrant.EnsureAsync<AiBudgetAdminGrantMarker>(
            tenantContext, IdentityServiceConstants.AiBudgetAdminRole, IdentityServiceConstants.AiBudgetAdminGrantKey,
            logger, waitForAdministrator: true).ConfigureAwait(false);
    }
}
