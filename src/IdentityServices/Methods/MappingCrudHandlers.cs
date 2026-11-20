using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.ConstructionKit.Contracts;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     The cross-tenant grant audit of the mapping methods: one event in this and the source tenant. A failure is
///     logged and never fails the call, as on the REST endpoints.
/// </summary>
internal static class MappingGrantAudit
{
    public static async Task RecordAsync(IdentityMethodCall call, string eventName, RtExternalTenantUserMapping mapping,
        IReadOnlyList<string>? groupNames = null)
    {
        try
        {
            var tenantId = call.Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantId();
            groupNames ??= await GroupNamesAsync(call, mapping).ConfigureAwait(false);
            await call.Services.GetRequiredService<ICrossTenantGrantAuditRecorder>().RecordGrantAsync(eventName, tenantId,
                await CrossTenantMethodSupport.CallerNameAsync(call, tenantId).ConfigureAwait(false), mapping,
                groupNames).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            call.Services.GetRequiredService<ILogger<IdentityMethodCall>>().LogWarning(ex,
                "Audit event {EventName} of mapping {MappingId} could not be recorded", eventName, mapping.RtId);
        }
    }

    /// <summary>The mapping's group names for an audit event; a read error yields none.</summary>
    public static async Task<IReadOnlyList<string>> GroupNamesAsync(IdentityMethodCall call,
        RtExternalTenantUserMapping mapping)
    {
        try
        {
            return await call.Services.GetRequiredService<IGroupStore>()
                .GetGroupNamesForExternalUserMappingAsync(mapping.RtId).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            call.Services.GetRequiredService<ILogger<IdentityMethodCall>>().LogWarning(ex,
                "Group names of mapping {MappingId} could not be read for the audit event", mapping.RtId);
            return [];
        }
    }
}

/// <summary>
///     Handler of <c>System.Identity/ExternalTenantUserMapping.UpdateMapping-1</c> (System.Identity 3.8.0): replaces the roles of
///     a mapping, as <c>PUT {tenant}/v1/externalTenantUserMappings/{rtId}</c> did. The role change guard refuses a role
///     the caller does not hold or a grant to the caller itself (<c>METHOD_FORBIDDEN</c>); the grant audit records
///     <c>GrantChanged</c>.
/// </summary>
internal sealed class ExternalTenantUserMappingUpdateMappingHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ExternalTenantUserMappingUpdateMappingParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ExternalTenantUserMappingUpdateMappingParameters parameters, CancellationToken cancellationToken)
    {
        var store = call.Services.GetRequiredService<IExternalTenantUserMappingStore>();
        var existing = await store.GetByIdAsync(targetRtId).ConfigureAwait(false);
        if (existing == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details["sourceTenantId"] = existing.SourceTenantId;
        var roleIds = parameters.RoleIds?.ToList();
        var decision = await call.Services.GetRequiredService<IRoleChangeGuard>().EvaluateAsync(call.Caller,
            new RoleGraphChange.MappingRoles(targetRtId.ToString(), null, null, roleIds ?? []), cancellationToken)
            .ConfigureAwait(false);
        if (!decision.IsAllowed)
        {
            return call.Refuse(decision);
        }

        existing.MappedRoleIds = roleIds != null ? new AttributeStringValueList(roleIds) : null;
        await store.StoreAsync(existing).ConfigureAwait(false);
        await MappingGrantAudit.RecordAsync(call, CrossTenantGrantAuditEvents.GrantChanged, existing)
            .ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/ExternalTenantUserMapping.DeleteMapping-1</c> (System.Identity 3.8.0): deletes a mapping and
///     its group memberships, as <c>DELETE {tenant}/v1/externalTenantUserMappings/{rtId}</c> did. The role change guard decides
///     (a caller cannot remove their own mapping's grant); the grant audit records <c>GrantRemoved</c>.
/// </summary>
internal sealed class ExternalTenantUserMappingDeleteMappingHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<ExternalTenantUserMappingDeleteMappingParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        ExternalTenantUserMappingDeleteMappingParameters parameters, CancellationToken cancellationToken)
    {
        var store = call.Services.GetRequiredService<IExternalTenantUserMappingStore>();
        var existing = await store.GetByIdAsync(targetRtId).ConfigureAwait(false);
        if (existing == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details["sourceTenantId"] = existing.SourceTenantId;
        var decision = await call.Services.GetRequiredService<IRoleChangeGuard>().EvaluateAsync(call.Caller,
            new RoleGraphChange.MappingDeleted(targetRtId.ToString()), cancellationToken).ConfigureAwait(false);
        if (!decision.IsAllowed)
        {
            return call.Refuse(decision);
        }

        // Group names before the removal: the mapping's GroupMember edges go with it.
        var groupNames = await MappingGrantAudit.GroupNamesAsync(call, existing).ConfigureAwait(false);
        await store.RemoveAsync(targetRtId).ConfigureAwait(false);
        await MappingGrantAudit.RecordAsync(call, CrossTenantGrantAuditEvents.GrantRemoved, existing, groupNames)
            .ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
