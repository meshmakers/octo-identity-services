using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;

namespace IdentityServerPersistence.Services.FileRoles;

/// <summary>
///     Tells whether a tenant has the System.Files CK model (AB#6467). A seam so tests can switch it.
/// </summary>
internal interface IFilesModelProbe
{
    bool HasFilesModel(string tenantId);
}

/// <summary>The production probe: System.Files/FileSystemEntity in the tenant's CK cache.</summary>
internal sealed class CkCacheFilesModelProbe(ICkCacheService ckCacheService) : IFilesModelProbe
{
    public bool HasFilesModel(string tenantId) =>
        ckCacheService.TryGetRtCkType(tenantId, new RtCkId<CkTypeId>("System.Files/FileSystemEntity"), out _);
}
