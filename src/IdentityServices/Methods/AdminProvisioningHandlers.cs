using System.Globalization;
using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.AdminProvisioning;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the <c>ExternalTenantUserMapping</c> methods (declared in <c>ck-externalTenantUserMapping.yaml</c>).</summary>
internal static class AdminProvisioningMethodErrors
{
    public const string TenantNotFound = "TENANT_NOT_FOUND";
    public const string SourceTenantNotAncestor = "SOURCE_TENANT_NOT_ANCESTOR";
    public const string MappingAlreadyExists = "MAPPING_ALREADY_EXISTS";
    public const string CallerNotAUser = "CALLER_NOT_A_USER";
    public const string HomeIdentityUnresolved = "HOME_IDENTITY_UNRESOLVED";
    public const string TenantInitializing = "TENANT_INITIALIZING";
    public const string MappingNotFound = "MAPPING_NOT_FOUND";
    public const string SourceTenantNotPermitted = "SOURCE_TENANT_NOT_PERMITTED";
    public const string UnknownGroup = "UNKNOWN_GROUP";

    /// <summary>Parameter of <see cref="MappingAlreadyExists" />: the runtime id of the existing mapping.</summary>
    public const string ExistingMappingIdParameter = "existingMappingId";

    /// <summary>Parameter of <see cref="UnknownGroup" />: the group ids that are no group of the tenant (comma separated).</summary>
    public const string UnknownGroupIdsParameter = "unknownGroupIds";

    /// <summary>Parameter of <see cref="CallerNotAUser" />: <c>subject</c> or <c>tenant</c> - what the caller's token lacks.</summary>
    public const string MissingParameter = "missing";

    /// <summary>Audit detail: the target tenant of the call.</summary>
    public const string TargetTenantIdDetail = "targetTenantId";

    /// <summary>Audit detail: the runtime id of the mapping written or removed.</summary>
    public const string MappingRtIdDetail = "mappingRtId";
}

/// <summary>
///     The declaring type of the static <c>ExternalTenantUserMapping</c> methods. The GraphQL gateway checks the caller's
///     <c>Write</c> data permission on it before it dispatches a static method; the handlers check the same for REST facades.
/// </summary>
internal static class ExternalTenantUserMappingMethodType
{
    public static readonly RtCkId<CkTypeId> CkTypeId = RtEntityExtensions.GetRtCkTypeId<RtExternalTenantUserMapping>();
}

/// <summary>
///     Shared flow of the static <c>ExternalTenantUserMapping</c> methods (System.Identity 3.5.0): caller rule, tenant
///     binding, and exactly one <c>Identity.Method</c> event per call (success, every refusal, <c>METHOD_HANDLER_FAILED</c>
///     for an exception). Audit details: <c>targetTenantId</c>, <c>sourceTenantId</c>, <c>mappingRtId</c>, never a token.
/// </summary>
internal abstract class ExternalTenantUserMappingHandlerBase<TParameters, TResult>(IServiceProvider services)
    : ICkMethodHandler<TParameters, TResult> where TParameters : class where TResult : class
{
    protected IServiceProvider Services { get; } = services;

    public Task<CkMethodOutcome<TResult>> HandleAsync(CkMethodContext<TParameters> context,
        CancellationToken cancellationToken)
    {
        var call = context.CallerPrincipal == null ? null : new IdentityMethodCall(Services, context.CallerPrincipal);
        return IdentityMethodAudit.RunAsync(Services, context, call, () => RunAsync(context, call, cancellationToken),
            outcome => outcome.Failure?.Code);
    }

    /// <summary>
    ///     The caller rule. Default: the REST policy of <c>AdminProvisioningController</c>
    ///     (<see cref="IdentityMethodCallerRules.IsTenantAdministrator" />: <c>TenantManagement</c> or <c>UserManagement</c>).
    /// </summary>
    protected virtual bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    /// <summary>Applies the method; the caller is admitted and the tenant of the call is bound.</summary>
    protected abstract Task<CkMethodOutcome<TResult>> ApplyAsync(IdentityMethodCall call, string tenantId,
        TParameters parameters, CancellationToken cancellationToken);

    private async Task<CkMethodOutcome<TResult>> RunAsync(CkMethodContext<TParameters> context, IdentityMethodCall? call,
        CancellationToken cancellationToken)
    {
        if (call == null || !IsAdmitted(call.Principal))
        {
            return CkMethodOutcome<TResult>.Forbidden("role-required");
        }

        if (!await Services.GetRequiredService<IMethodTenantAccessor>().BindAsync(context.TenantId).ConfigureAwait(false))
        {
            return CkMethodOutcome<TResult>.TargetNotFound();
        }

        if (await call.CheckTypeWritableAsync(ExternalTenantUserMappingMethodType.CkTypeId, cancellationToken)
                .ConfigureAwait(false) is { } denied)
        {
            return CkMethodOutcome<TResult>.Fail(denied);
        }

        return await ApplyAsync(call, context.TenantId, context.Parameters, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    ///     The target-tenant rule of the provisioning methods (as the REST filter): <paramref name="targetTenantId" /> must be
    ///     the caller's tenant or lie in its subtree. Records the target in the audit details.
    /// </summary>
    protected static async Task<CkMethodFailure?> CheckTargetAsync(IdentityMethodCall call, string methodId,
        string? targetTenantId)
    {
        if (string.IsNullOrWhiteSpace(targetTenantId))
        {
            return CrossTenantMethodSupport.ValidationFailed("targetTenantId");
        }

        call.Details[AdminProvisioningMethodErrors.TargetTenantIdDetail] = targetTenantId;
        return await CrossTenantMethodSupport.CheckTargetTenantAsync(call, methodId, targetTenantId)
            .ConfigureAwait(false);
    }

    /// <summary>The service that writes into the target tenant (created per call, from the services of the invocation).</summary>
    protected AdminProvisioningService Provisioning => ActivatorUtilities.CreateInstance<AdminProvisioningService>(Services);

    /// <summary>The declared failure of a provisioning outcome, or <c>null</c> when it is a success.</summary>
    protected static CkMethodFailure? FailureOf(AdminProvisioningOutcome outcome) => outcome.Status switch
    {
        AdminProvisioningStatus.TenantNotFound => new CkMethodFailure(AdminProvisioningMethodErrors.TenantNotFound),
        AdminProvisioningStatus.SourceTenantNotAncestor =>
            new CkMethodFailure(AdminProvisioningMethodErrors.SourceTenantNotAncestor),
        AdminProvisioningStatus.AlreadyExists => new CkMethodFailure(AdminProvisioningMethodErrors.MappingAlreadyExists,
            new Dictionary<string, string>
            {
                [AdminProvisioningMethodErrors.ExistingMappingIdParameter] = outcome.Mapping!.RtId.ToString()
            }),
        AdminProvisioningStatus.HomeIdentityUnresolved =>
            new CkMethodFailure(AdminProvisioningMethodErrors.HomeIdentityUnresolved),
        AdminProvisioningStatus.TenantInitializing => new CkMethodFailure(AdminProvisioningMethodErrors.TenantInitializing),
        AdminProvisioningStatus.MappingNotFound => new CkMethodFailure(AdminProvisioningMethodErrors.MappingNotFound),
        _ => null
    };

    /// <summary>The result record of a stored mapping.</summary>
    protected static RtAdminProvisioningResultRecord ToRecord(IdentityMethodCall call,
        RtExternalTenantUserMapping mapping, IEnumerable<string> groupNames, string? outcome = null)
    {
        call.Details[AdminProvisioningMethodErrors.MappingRtIdDetail] = mapping.RtId.ToString();
        call.Details["sourceTenantId"] = mapping.SourceTenantId;
        if (outcome != null)
        {
            call.Details["provisioningOutcome"] = outcome;
        }

        return new RtAdminProvisioningResultRecord
        {
            MappingRtId = mapping.RtId.ToString(),
            SourceTenantId = mapping.SourceTenantId,
            SourceUserId = mapping.SourceUserId,
            SourceUserName = mapping.SourceUserName,
            RoleIds = new AttributeStringValueList(mapping.MappedRoleIds?.ToList() ?? []),
            GroupNames = new AttributeStringValueList(groupNames.ToList()),
            Outcome = outcome
        };
    }
}

/// <summary>
///     Handler of <c>System.Identity/ExternalTenantUserMapping.ProvisionAdmin-1</c>: creates a mapping of a source-tenant user
///     in the target tenant with the given roles (one carrying <c>TenantManagement</c> also joins <c>TenantOwners</c>) and
///     registers the source tenant as the target's login parent. REST facade: <c>POST {tenant}/v1/adminProvisioning/{targetTenantId}</c>.
/// </summary>
/// <remarks>
///     Before any write: the caller rule, the target-tenant rule (<c>tenant-out-of-scope</c>), the target tenant exists
///     (<c>TENANT_NOT_FOUND</c>), the source tenant is a registry ancestor of the target (<c>SOURCE_TENANT_NOT_ANCESTOR</c>)
///     and no mapping exists for the source user (<c>MAPPING_ALREADY_EXISTS</c>, naming the existing one). Data access beyond
///     the call's tenant: the mapping, the <c>TenantOwners</c> membership and the identity provider in the target tenant,
///     written through the system context like the REST endpoint did; the target-tenant rule is the access rule for them.
/// </remarks>
internal sealed class ExternalTenantUserMappingProvisionAdminHandler(IServiceProvider services)
    : ExternalTenantUserMappingHandlerBase<ExternalTenantUserMappingProvisionAdminParameters,
        ExternalTenantUserMappingProvisionAdminResult>(services)
{
    protected override async Task<CkMethodOutcome<ExternalTenantUserMappingProvisionAdminResult>> ApplyAsync(
        IdentityMethodCall call, string tenantId, ExternalTenantUserMappingProvisionAdminParameters parameters,
        CancellationToken cancellationToken)
    {
        if (await CheckTargetAsync(call, SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
                parameters.TargetTenantId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        var outcome = await Provisioning.CreateAsync(parameters.TargetTenantId, parameters.SourceTenantId,
            parameters.SourceUserId, parameters.SourceUserName, parameters.RoleIds,
            await CrossTenantMethodSupport.CallerNameAsync(call, tenantId).ConfigureAwait(false)).ConfigureAwait(false);
        return FailureOf(outcome) is { } failure
            ? failure
            : new ExternalTenantUserMappingProvisionAdminResult
                { Value = ToRecord(call, outcome.Mapping!, outcome.GroupNames ?? []) };
    }
}

/// <summary>
///     Handler of <c>System.Identity/ExternalTenantUserMapping.ProvisionAdminWithGroups-1</c>: creates a mapping of a
///     source-tenant user in the target tenant as a member of the given target-tenant groups (ids that name no group there
///     are skipped). REST facade: <c>POST {tenant}/v1/adminProvisioning/{targetTenantId}/withGroups</c>. Same checks as
///     <see cref="ExternalTenantUserMappingProvisionAdminHandler" />.
/// </summary>
internal sealed class ExternalTenantUserMappingProvisionAdminWithGroupsHandler(IServiceProvider services)
    : ExternalTenantUserMappingHandlerBase<ExternalTenantUserMappingProvisionAdminWithGroupsParameters,
        ExternalTenantUserMappingProvisionAdminWithGroupsResult>(services)
{
    protected override async Task<CkMethodOutcome<ExternalTenantUserMappingProvisionAdminWithGroupsResult>> ApplyAsync(
        IdentityMethodCall call, string tenantId, ExternalTenantUserMappingProvisionAdminWithGroupsParameters parameters,
        CancellationToken cancellationToken)
    {
        if (await CheckTargetAsync(call, SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminWithGroupsMethodId,
                parameters.TargetTenantId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        var outcome = await Provisioning.CreateWithGroupsAsync(parameters.TargetTenantId, parameters.SourceTenantId,
            parameters.SourceUserId, parameters.SourceUserName, parameters.GroupIds,
            await CrossTenantMethodSupport.CallerNameAsync(call, tenantId).ConfigureAwait(false)).ConfigureAwait(false);
        return FailureOf(outcome) is { } failure
            ? failure
            : new ExternalTenantUserMappingProvisionAdminWithGroupsResult
                { Value = ToRecord(call, outcome.Mapping!, outcome.GroupNames ?? []) };
    }
}

/// <summary>
///     Handler of <c>System.Identity/ExternalTenantUserMapping.ProvisionCurrentUser-1</c>: provisions the calling user in the
///     target tenant as an administrator. REST facade: <c>POST {tenant}/v1/adminProvisioning/{targetTenantId}/provisionCurrentUser</c>.
/// </summary>
/// <remarks>
///     The user is the validated caller: its subject and the tenant its token was issued for, never a parameter. A caller
///     without a subject (client credentials) or without a token tenant is <c>CALLER_NOT_A_USER</c>. A cross-tenant shadow
///     user is provisioned as its home identity; an unresolvable one is <c>HOME_IDENTITY_UNRESOLVED</c> and nothing is
///     written. The user name comes from the user record of the caller's tenant (the token's profile claims are not part of
///     the method caller). A target tenant that is still initializing is retried with back-off, then
///     <c>TENANT_INITIALIZING</c>. The result's <c>outcome</c> is <c>created</c>, <c>repaired</c> or
///     <c>already-provisioned</c>.
/// </remarks>
internal sealed class ExternalTenantUserMappingProvisionCurrentUserHandler(IServiceProvider services)
    : ExternalTenantUserMappingHandlerBase<ExternalTenantUserMappingProvisionCurrentUserParameters,
        ExternalTenantUserMappingProvisionCurrentUserResult>(services)
{
    protected override async Task<CkMethodOutcome<ExternalTenantUserMappingProvisionCurrentUserResult>> ApplyAsync(
        IdentityMethodCall call, string tenantId, ExternalTenantUserMappingProvisionCurrentUserParameters parameters,
        CancellationToken cancellationToken)
    {
        if (await CheckTargetAsync(call, SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId,
                parameters.TargetTenantId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        var userId = call.Principal.SubjectId;
        var callerTenantId = CrossTenantMethodSupport.CallerTenantId(call.Principal);
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(callerTenantId))
        {
            return new CkMethodFailure(AdminProvisioningMethodErrors.CallerNotAUser,
                new Dictionary<string, string>
                {
                    [AdminProvisioningMethodErrors.MissingParameter] = string.IsNullOrEmpty(userId) ? "subject" : "tenant"
                });
        }

        var (outcome, _) = await Provisioning.ProvisionCurrentUserAsync(parameters.TargetTenantId, userId, callerTenantId,
            null, await CrossTenantMethodSupport.CallerNameAsync(call, tenantId).ConfigureAwait(false),
            cancellationToken).ConfigureAwait(false);
        return FailureOf(outcome) is { } failure
            ? failure
            : new ExternalTenantUserMappingProvisionCurrentUserResult
            {
                Value = ToRecord(call, outcome.Mapping!, outcome.GroupNames ?? [], outcome.ProvisioningOutcome)
            };
    }
}

/// <summary>
///     Handler of <c>System.Identity/ExternalTenantUserMapping.RemoveAdminProvisioning-1</c>: deletes a mapping in the target
///     tenant. REST facade: <c>DELETE {tenant}/v1/adminProvisioning/{targetTenantId}/{mappingRtId}</c>. A mapping id that
///     is no object id or names no mapping is <c>MAPPING_NOT_FOUND</c>.
/// </summary>
internal sealed class ExternalTenantUserMappingRemoveAdminProvisioningHandler(IServiceProvider services)
    : ICkMethodHandler<ExternalTenantUserMappingRemoveAdminProvisioningParameters>
{
    public Task<CkMethodOutcome> HandleAsync(
        CkMethodContext<ExternalTenantUserMappingRemoveAdminProvisioningParameters> context,
        CancellationToken cancellationToken)
    {
        var call = context.CallerPrincipal == null ? null : new IdentityMethodCall(services, context.CallerPrincipal);
        return IdentityMethodAudit.RunAsync(services, context, call, () => RunAsync(context, call, cancellationToken),
            outcome => outcome.Failure?.Code);
    }

    private async Task<CkMethodOutcome> RunAsync(
        CkMethodContext<ExternalTenantUserMappingRemoveAdminProvisioningParameters> context, IdentityMethodCall? call,
        CancellationToken cancellationToken)
    {
        if (call == null || !IdentityMethodCallerRules.IsTenantAdministrator(call.Principal))
        {
            return CkMethodOutcome.Forbidden("role-required");
        }

        if (!await services.GetRequiredService<IMethodTenantAccessor>().BindAsync(context.TenantId).ConfigureAwait(false))
        {
            return CkMethodOutcome.TargetNotFound();
        }

        if (await call.CheckTypeWritableAsync(ExternalTenantUserMappingMethodType.CkTypeId, cancellationToken)
                .ConfigureAwait(false) is { } denied)
        {
            return CkMethodOutcome.Fail(denied);
        }

        var parameters = context.Parameters;
        if (string.IsNullOrWhiteSpace(parameters.TargetTenantId))
        {
            return CkMethodOutcome.Fail(CrossTenantMethodSupport.ValidationFailed("targetTenantId"));
        }

        call.Details[AdminProvisioningMethodErrors.TargetTenantIdDetail] = parameters.TargetTenantId;
        if (await CrossTenantMethodSupport.CheckTargetTenantAsync(call,
                SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId, parameters.TargetTenantId)
                .ConfigureAwait(false) is { } refused)
        {
            return CkMethodOutcome.Fail(refused);
        }

        if (!OctoObjectId.TryParse(parameters.MappingRtId, out var mappingRtId))
        {
            return CkMethodOutcome.Fail(new CkMethodFailure(AdminProvisioningMethodErrors.MappingNotFound));
        }

        call.Details[AdminProvisioningMethodErrors.MappingRtIdDetail] = mappingRtId.ToString();
        var outcome = await ActivatorUtilities.CreateInstance<AdminProvisioningService>(services).DeleteAsync(
            parameters.TargetTenantId, mappingRtId,
            await CrossTenantMethodSupport.CallerNameAsync(call, context.TenantId).ConfigureAwait(false))
            .ConfigureAwait(false);
        return outcome.Status switch
        {
            AdminProvisioningStatus.Removed => CkMethodOutcome.Ok(),
            AdminProvisioningStatus.TenantNotFound =>
                CkMethodOutcome.Fail(new CkMethodFailure(AdminProvisioningMethodErrors.TenantNotFound)),
            _ => CkMethodOutcome.Fail(new CkMethodFailure(AdminProvisioningMethodErrors.MappingNotFound))
        };
    }
}

/// <summary>
///     Handler of <c>System.Identity/ExternalTenantUserMapping.CreateMapping-1</c>: creates a mapping of a source-tenant user
///     in the tenant of the call, with roles and groups of that tenant. REST facade:
///     <c>POST {tenant}/v1/externalTenantUserMappings</c>.
/// </summary>
/// <remarks>
///     <para>
///         The cross-tenant checks of the REST create, before any write: the source tenant is a registry ancestor of this
///         tenant or permits it, and the user exists there (<c>SOURCE_TENANT_NOT_PERMITTED</c>, one answer for every
///         refused source); no mapping exists for the source user (<c>MAPPING_ALREADY_EXISTS</c>); every group id names a
///         group of this tenant (<c>UNKNOWN_GROUP</c>); the role change guard admits the roles the mapping gains
///         (<c>METHOD_FORBIDDEN</c> with the guard's <c>reason</c>). The stored user name is the one of the source
///         tenant's user record.
///     </para>
///     <para>
///         Caller rule: <c>UserManagement</c> (<see cref="IdentityMethodCallerRules.IsAdministrator" />, the REST policy
///         <c>IdentityUserAdministrationWritePolicy</c>). The generic create of the type stays available until the next
///         major sets <c>replacesGenericCreate</c> on this method.
///     </para>
/// </remarks>
internal sealed class ExternalTenantUserMappingCreateMappingHandler(IServiceProvider services)
    : ExternalTenantUserMappingHandlerBase<ExternalTenantUserMappingCreateMappingParameters,
        ExternalTenantUserMappingCreateMappingResult>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) => IdentityMethodCallerRules.IsAdministrator(principal);

    protected override async Task<CkMethodOutcome<ExternalTenantUserMappingCreateMappingResult>> ApplyAsync(
        IdentityMethodCall call, string tenantId, ExternalTenantUserMappingCreateMappingParameters parameters,
        CancellationToken cancellationToken)
    {
        var source = await Services.GetRequiredService<ISourceTenantGrantAdmission>().AdmitAsync(tenantId,
            parameters.SourceTenantId, parameters.SourceUserId, cancellationToken).ConfigureAwait(false);
        if (source == null)
        {
            return new CkMethodFailure(AdminProvisioningMethodErrors.SourceTenantNotPermitted);
        }

        call.Details["sourceTenantId"] = source.SourceTenantId;
        var mappingStore = Services.GetRequiredService<IExternalTenantUserMappingStore>();
        var duplicate = await mappingStore.FindBySourceUserAsync(source.SourceTenantId, source.SourceUserId)
            .ConfigureAwait(false);
        if (duplicate != null)
        {
            return new CkMethodFailure(AdminProvisioningMethodErrors.MappingAlreadyExists,
                new Dictionary<string, string>
                {
                    [AdminProvisioningMethodErrors.ExistingMappingIdParameter] = duplicate.RtId.ToString()
                });
        }

        var groupStore = Services.GetRequiredService<IGroupStore>();
        var groups = new List<RtGroup>();
        var unknown = new List<string>();
        foreach (var groupId in (parameters.GroupIds ?? []).Distinct(StringComparer.Ordinal))
        {
            var group = groupId != null && OctoObjectId.TryParse(groupId, out var rtId)
                ? await groupStore.FindByIdAsync(rtId).ConfigureAwait(false)
                : null;
            if (group == null)
            {
                unknown.Add(groupId ?? string.Empty);
            }
            else if (groups.All(g => g.RtId != group.RtId))
            {
                groups.Add(group);
            }
        }

        if (unknown.Count > 0)
        {
            return new CkMethodFailure(AdminProvisioningMethodErrors.UnknownGroup,
                new Dictionary<string, string>
                {
                    [AdminProvisioningMethodErrors.UnknownGroupIdsParameter] = string.Join(",", unknown)
                });
        }

        var roleIds = parameters.RoleIds?.ToList();
        var decision = await Services.GetRequiredService<IRoleChangeGuard>().EvaluateAsync(call.Caller,
            new RoleGraphChange.MappingRoles(null, source.SourceTenantId, source.SourceUserName, roleIds ?? [],
                groups.Select(g => g.RtId.ToString()).ToList()), cancellationToken).ConfigureAwait(false);
        if (!decision.IsAllowed)
        {
            return call.Refuse(decision).Failure!;
        }

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = source.SourceTenantId,
            SourceUserId = source.SourceUserId,
            SourceUserName = source.SourceUserName,
            MappedRoleIds = roleIds != null ? new AttributeStringValueList(roleIds) : null
        };

        if (groups.Count > 0)
        {
            await mappingStore.InsertWithGroupsAsync(mapping, groups).ConfigureAwait(false);
        }
        else
        {
            await mappingStore.StoreAsync(mapping).ConfigureAwait(false);
        }

        var groupNames = groups.Select(g => g.GroupName).ToList();
        try
        {
            await Services.GetRequiredService<ICrossTenantGrantAuditRecorder>().RecordGrantAsync(
                CrossTenantGrantAuditEvents.GrantCreated, tenantId,
                await CrossTenantMethodSupport.CallerNameAsync(call, tenantId).ConfigureAwait(false), mapping,
                groupNames).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Services.GetRequiredService<ILogger<ExternalTenantUserMappingCreateMappingHandler>>().LogWarning(ex,
                "Audit event {EventName} of mapping {MappingId} could not be recorded",
                CrossTenantGrantAuditEvents.GrantCreated, mapping.RtId);
        }

        call.Details["groups"] = groups.Count.ToString(CultureInfo.InvariantCulture);
        return new ExternalTenantUserMappingCreateMappingResult { Value = ToRecord(call, mapping, groupNames) };
    }
}
