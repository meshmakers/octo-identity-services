using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
/// Service responsible for provisioning (finding or creating) local shadow users
/// in a child tenant for cross-tenant authenticated users.
/// </summary>
public interface ICrossTenantUserProvisioningService
{
    /// <summary>
    /// Finds or creates a local shadow user in the current tenant for a cross-tenant authenticated user.
    /// Creates the user with username pattern "xt_{sourceTenant}_{sourceUserName}" and syncs
    /// profile fields and the ExternalTenantUserMapping. An existing shadow user of the same person
    /// (see <see cref="FindCrossTenantUserAsync"/>) is reused instead of creating a second one.
    /// Roles are not copied onto the user: mapping and group roles are resolved at token time
    /// (<see cref="IGroupRoleResolver.ResolveEffectiveUserRoleIdsAsync"/>, AB#5708).
    /// </summary>
    /// <param name="crossTenantResult">The cross-tenant authentication result containing source user info.</param>
    /// <param name="childTenantId">The tenant ID where the shadow user should be created.</param>
    /// <returns>The local shadow user, or null if creation failed.</returns>
    Task<RtUser?> FindOrCreateCrossTenantUserAsync(
        CrossTenantAuthResult crossTenantResult, string childTenantId);

    /// <summary>
    /// Finds the local shadow user of the person behind <paramref name="crossTenantResult"/> without
    /// creating one: the user named "xt_{sourceTenant}_{sourceUserName}" if it exists, otherwise a
    /// shadow user of the same identity created by another login path (same home identity after
    /// unwinding the xt_ chain, no password). Returns null when the person has no shadow user yet.
    /// </summary>
    Task<RtUser?> FindCrossTenantUserAsync(CrossTenantAuthResult crossTenantResult);

    /// <summary>
    /// True when an admin created an ExternalTenantUserMapping in the current tenant for the source
    /// user or for any identity its xt_ chain unwinds to (explicit provisioning, AB#5015/AB#5708).
    /// </summary>
    Task<bool> IsExplicitlyProvisionedAsync(CrossTenantAuthResult crossTenantResult);
}
