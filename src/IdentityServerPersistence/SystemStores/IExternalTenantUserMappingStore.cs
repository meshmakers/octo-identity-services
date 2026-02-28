using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
/// Store for managing cross-tenant user role mappings.
/// Each mapping links a user from a parent (source) tenant to roles in the current (child) tenant.
/// </summary>
public interface IExternalTenantUserMappingStore
{
    /// <summary>
    /// Finds a mapping by the source tenant ID and source user ID.
    /// </summary>
    Task<RtExternalTenantUserMapping?> FindBySourceUserAsync(string sourceTenantId, string sourceUserId);

    /// <summary>
    /// Gets all mappings for the current tenant with optional pagination.
    /// </summary>
    Task<IEnumerable<RtExternalTenantUserMapping>> GetAllAsync(int? skip = null, int? take = null);

    /// <summary>
    /// Gets all mappings from a specific source tenant.
    /// </summary>
    Task<IEnumerable<RtExternalTenantUserMapping>> GetBySourceTenantAsync(string sourceTenantId);

    /// <summary>
    /// Stores (creates or updates) a mapping.
    /// </summary>
    Task StoreAsync(RtExternalTenantUserMapping mapping);

    /// <summary>
    /// Removes a mapping by its RtId.
    /// </summary>
    Task RemoveAsync(OctoObjectId rtId);

    /// <summary>
    /// Gets a mapping by its RtId.
    /// </summary>
    Task<RtExternalTenantUserMapping?> GetByIdAsync(OctoObjectId rtId);
}
