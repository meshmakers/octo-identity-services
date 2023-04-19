using System.Collections.Generic;
using System.Threading.Tasks;
using Duende.IdentityServer.Models;
using Meshmakers.Octo.Common.Shared;
using Meshmakers.Octo.SystematizedData.Persistence;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Meshmakers.Octo.SystematizedData.Persistence.SystemStores;

namespace Meshmakers.Octo.Backend.PolicyServices.Services;

internal class UserSchemaService : IUserSchemaService
{
    private readonly IOctoPermissionStore _permissionStore;
    private readonly IOctoResourceStore _resourceStore;
    private readonly ISystemContext _systemContext;

    public UserSchemaService(ISystemContext systemContext,
        IOctoResourceStore resourceStore, IOctoPermissionStore permissionStore)
    {
        _systemContext = systemContext;
        _resourceStore = resourceStore;
        _permissionStore = permissionStore;
    }

    public async Task SetupAsync()
    {
        using var session = await _systemContext.StartSystemSessionAsync();
        session.StartTransaction();

        var version =
            await _systemContext.GetConfigurationAsync(session,
                PolicyServiceConstants.PolicyServiceSchemaVersionKey, 0);
        if (version < PolicyServiceConstants.PolicyServiceSchemaVersionValue)
        {
            await CreateApiScopes();
            await CreateApiResources();
            await CreateSystemPermissions();

            await _systemContext.SetConfigurationAsync(session,
                PolicyServiceConstants.PolicyServiceSchemaVersionKey,
                PolicyServiceConstants.PolicyServiceSchemaVersionValue);
        }

        await session.CommitTransactionAsync();
    }

    private async Task CreateSystemPermissions()
    {
        await _permissionStore.EnsurePermission(CommonConstants.PermissionIds.PermissionRead);
        await _permissionStore.EnsurePermission(CommonConstants.PermissionIds.PermissionWrite);
        await _permissionStore.EnsurePermission(CommonConstants.PermissionIds.PermissionRoleRead);
        await _permissionStore.EnsurePermission(CommonConstants.PermissionIds.PermissionRoleWrite);
    }

    private async Task CreateApiScopes()
    {
        await _resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.PolicyApiFullAccess,
            CommonConstants.PolicyApiFullAccessDisplayName));
        await _resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.PolicyApiReadOnly,
            CommonConstants.PolicyApiReadOnlyDisplayName));
    }

    private async Task CreateApiResources()
    {
        await _resourceStore.GetOrCreateApiResourceAsync(new OctoApiResource
        {
            Name = CommonConstants.PolicyApi,
            DisplayName = CommonConstants.PolicyApiDisplayName,
            Description = CommonConstants.PolicyApiDescription,
            Enabled = true,
            Scopes = new List<string>
            {
                CommonConstants.PolicyApiFullAccess,
                CommonConstants.PolicyApiReadOnly
            }
        });
    }
}
