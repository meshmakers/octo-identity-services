using Duende.IdentityServer.Models;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

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
        using var session = await _systemContext.GetSystemSessionAsync();
        session.StartTransaction();

        var policyConfiguration =
            await _systemContext.GetConfigurationAsync(session,
                PolicyServiceConstants.PolicyServiceSchemaVersionKey,
                new PolicyConfiguration { Version = PolicyServiceConstants.PolicyServiceSchemaVersionValue });
        if (policyConfiguration == null || policyConfiguration.Version < PolicyServiceConstants.PolicyServiceSchemaVersionValue)
        {
            await CreateApiScopes();
            await CreateApiResources();
            await CreateSystemPermissions();

            await _systemContext.SetConfigurationAsync(session,
                PolicyServiceConstants.PolicyServiceSchemaVersionKey, new PolicyConfiguration
                {
                    Version = PolicyServiceConstants.PolicyServiceSchemaVersionValue
                });
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
        await _resourceStore.GetOrCreateApiResourceAsync(new RtApiResource
        {
            Name = CommonConstants.PolicyApi,
            DisplayName = CommonConstants.PolicyApiDisplayName,
            Description = CommonConstants.PolicyApiDescription,
            Enabled = true,
            Scopes = new AttributeStringValueList
            {
                CommonConstants.PolicyApiFullAccess,
                CommonConstants.PolicyApiReadOnly
            }
        });
    }

    private class PolicyConfiguration
    {
        public int Version { get; set; }
    }
}