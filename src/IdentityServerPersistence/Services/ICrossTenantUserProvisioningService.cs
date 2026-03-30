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
    /// profile fields, ExternalTenantUserMapping, and mapped roles.
    /// </summary>
    /// <param name="crossTenantResult">The cross-tenant authentication result containing source user info.</param>
    /// <param name="childTenantId">The tenant ID where the shadow user should be created.</param>
    /// <returns>The local shadow user, or null if creation failed.</returns>
    Task<RtUser?> FindOrCreateCrossTenantUserAsync(
        CrossTenantAuthResult crossTenantResult, string childTenantId);
}
