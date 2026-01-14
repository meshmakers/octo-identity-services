using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public class PermissionStore : IOctoPermissionStore
{
    private readonly ITenantRepository _tenantRepository;

    public PermissionStore(IMultiTenancyResolverService multiTenancyResolverService)
    {
        _tenantRepository = multiTenancyResolverService.GetTenantRepository();
    }

    public async Task StorePermissionAsync(RtPermission octoPermission)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var persistentPermission = await GetPermissionById(octoPermission.PermissionId);
        if (persistentPermission == null)
        {
            await _tenantRepository.InsertOneRtEntityAsync(session, octoPermission);
        }
        else
        {
            await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, persistentPermission.RtId,
                octoPermission);
        }

        await session.CommitTransactionAsync();
    }

    public async Task<RtPermission?> GetPermissionById(string permissionId)
    {
        ArgumentValidation.ValidateString(nameof(permissionId), permissionId);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtPermission.PermissionId), FieldFilterOperator.Equals, permissionId);

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtPermission>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.FirstOrDefault();
    }

    public async Task EnsurePermission(string permissionId)
    {
        var permission = await GetPermissionById(permissionId);
        if (permission == null)
        {
            permission = new RtPermission
            {
                PermissionId = permissionId
            };
            await StorePermissionAsync(permission);
        }
    }
}