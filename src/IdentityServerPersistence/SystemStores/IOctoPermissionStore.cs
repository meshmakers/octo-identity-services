using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public interface IOctoPermissionStore
{
    Task StorePermissionAsync(RtPermission octoPermission);
    Task<RtPermission?> GetPermissionById(string permissionId);

    Task EnsurePermission(string permissionId);
}