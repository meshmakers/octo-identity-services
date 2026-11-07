using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;

/// <summary>
///     Names of the cross-tenant grant audit events (AB#8342, <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §7). Each name
///     is stored as the category of the runtime event (dotted, like every event category), so an administrator filters on
///     it — <c>LIKE "Identity.CrossTenant*"</c> reads them all.
/// </summary>
public static class CrossTenantGrantAuditEvents
{
    /// <summary>A source user lookup, hit or miss (detail <c>outcome</c>).</summary>
    public const string Lookup = "Identity.CrossTenantLookup";

    /// <summary>A mapping (grant) of a source user was created in the target tenant.</summary>
    public const string GrantCreated = "Identity.CrossTenantGrantCreated";

    /// <summary>A mapping (grant) was changed (roles or groups).</summary>
    public const string GrantChanged = "Identity.CrossTenantGrantChanged";

    /// <summary>A mapping (grant) was removed.</summary>
    public const string GrantRemoved = "Identity.CrossTenantGrantRemoved";

    /// <summary>The first token exchange of a source user into the target tenant created its shadow user with roles.</summary>
    public const string FirstExchange = "Identity.CrossTenantFirstExchange";

    /// <summary>A token exchange from a sibling (non-ancestor) source tenant was refused.</summary>
    public const string ExchangeRefused = "Identity.CrossTenantExchangeRefused";

    /// <summary>
    ///     The source tenant S changed the list of target tenants it permits (AB#8345). Written into S only, through
    ///     <see cref="IIdentityAuditService.StoreInfoAsync" /> by the permission routes.
    /// </summary>
    public const string GrantPermissionsChanged = "Identity.CrossTenantGrantPermissionsChanged";

    /// <summary>All names, for filters and documentation.</summary>
    public static readonly IReadOnlyList<string> All =
        [Lookup, GrantCreated, GrantChanged, GrantRemoved, FirstExchange, ExchangeRefused, GrantPermissionsChanged];
}

/// <summary>
///     Writes the cross-tenant grant audit events into the runtime event logs of the target tenant T and the source
///     tenant S (AB#8342). An event goes to S only when S is a registered tenant other than T; a grant event
///     (create/change/remove) additionally only when S is a registry ancestor of T or permits T
///     (<see cref="ISourceTenantGrantPolicy" />, AB#8436). Never carries the looked-up identifier, an e-mail address, a
///     token or a password. Never throws into the caller.
/// </summary>
public interface ICrossTenantGrantAuditRecorder
{
    /// <summary>One source user lookup (<see cref="CrossTenantGrantAuditEvents.Lookup" />).</summary>
    Task RecordLookupAsync(SourceUserLookupAuditEvent auditEvent);

    /// <summary>
    ///     A mapping change in T: <see cref="CrossTenantGrantAuditEvents.GrantCreated" />,
    ///     <see cref="CrossTenantGrantAuditEvents.GrantChanged" /> or <see cref="CrossTenantGrantAuditEvents.GrantRemoved" />.
    /// </summary>
    /// <param name="eventName">One of the three grant event names.</param>
    /// <param name="targetTenantId">T, the tenant the mapping lives in.</param>
    /// <param name="actorName">User name or client id of the administrator of T who made the change.</param>
    /// <param name="mapping">The mapping as stored (for a removal: as it was before).</param>
    /// <param name="groupNames">The T groups the mapping is a member of.</param>
    /// <remarks>
    ///     The source tenant and the user name of a mapping are supplied by the administrator of T. So that nobody can
    ///     place events into a foreign tenant's log, the event reaches S only when S is a registry ancestor of T or
    ///     permits T; otherwise it is recorded in T only (AB#8436).
    /// </remarks>
    Task RecordGrantAsync(string eventName, string targetTenantId, string actorName,
        RtExternalTenantUserMapping mapping, IReadOnlyList<string> groupNames);

    /// <summary>
    ///     The first exchange of a source user into T created its shadow user with roles
    ///     (<see cref="CrossTenantGrantAuditEvents.FirstExchange" />).
    /// </summary>
    /// <param name="targetTenantId">T (the request tenant of the exchange).</param>
    /// <param name="source">The source identity the exchange was admitted for.</param>
    /// <param name="shadowUserName">The <c>xt_</c> user created in T.</param>
    /// <param name="mapping">The mapping that granted the roles, if any; its T groups are read for the event.</param>
    /// <param name="roles">The role names the shadow user holds in T.</param>
    Task RecordFirstExchangeAsync(string targetTenantId, CrossTenantAuthResult source, string shadowUserName,
        RtExternalTenantUserMapping? mapping, IReadOnlyList<string> roles);

    /// <summary>
    ///     A refused exchange (<see cref="CrossTenantGrantAuditEvents.ExchangeRefused" />). Recorded only when the source
    ///     tenant is no registry ancestor of T (a sibling source); refusals of ancestor sources keep only the existing
    ///     failure event in T.
    /// </summary>
    Task RecordExchangeRefusedAsync(string targetTenantId, string sourceTenantId, string sourceUserId, string reason);
}

/// <inheritdoc />
internal sealed class CrossTenantGrantAuditRecorder(
    IIdentityAuditService auditService,
    ITenantRegistry tenantRegistry,
    ICrossTenantAncestryGuard ancestryGuard,
    ISourceTenantGrantPolicy grantPolicy,
    IGroupStore groupStore,
    ILogger<CrossTenantGrantAuditRecorder> logger) : ICrossTenantGrantAuditRecorder
{
    /// <inheritdoc />
    public Task RecordLookupAsync(SourceUserLookupAuditEvent auditEvent)
    {
        var outcome = auditEvent.IsHit ? "hit" : "miss";
        var details = new Dictionary<string, string>
        {
            ["outcome"] = outcome,
            ["actorTenantId"] = auditEvent.TargetTenantId,
            ["actorName"] = auditEvent.CallerName,
            ["sourceTenantId"] = auditEvent.SourceTenantId,
            ["targetTenantId"] = auditEvent.TargetTenantId
        };
        if (auditEvent.IsHit)
        {
            details["sourceUserId"] = auditEvent.SourceUserId ?? string.Empty;
            details["sourceUserName"] = auditEvent.SourceUserName ?? string.Empty;
        }

        // A miss names no user: the identifier the caller typed is never written, not even hashed.
        var message = auditEvent.IsHit
            ? $"'{auditEvent.CallerName}' of tenant '{auditEvent.TargetTenantId}' looked up user '{auditEvent.SourceUserName}' of tenant '{auditEvent.SourceTenantId}': hit"
            : $"'{auditEvent.CallerName}' of tenant '{auditEvent.TargetTenantId}' looked up a user of tenant '{auditEvent.SourceTenantId}': miss";

        return WriteAsync(CrossTenantGrantAuditEvents.Lookup, warning: false, auditEvent.TargetTenantId,
            auditEvent.SourceTenantExists ? auditEvent.SourceTenantId : null, message, details);
    }

    /// <inheritdoc />
    public Task RecordGrantAsync(string eventName, string targetTenantId, string actorName,
        RtExternalTenantUserMapping mapping, IReadOnlyList<string> groupNames)
    {
        var details = new Dictionary<string, string>
        {
            ["actorTenantId"] = targetTenantId,
            ["actorName"] = actorName,
            ["sourceTenantId"] = mapping.SourceTenantId,
            ["targetTenantId"] = targetTenantId,
            ["mappingId"] = mapping.RtId.ToString(),
            ["sourceUserId"] = mapping.SourceUserId,
            ["sourceUserName"] = mapping.SourceUserName,
            ["groupNames"] = string.Join(",", groupNames),
            ["roleIds"] = string.Join(",", mapping.MappedRoleIds?.ToList() ?? [])
        };
        var verb = eventName switch
        {
            CrossTenantGrantAuditEvents.GrantCreated => "granted",
            CrossTenantGrantAuditEvents.GrantChanged => "changed the grant of",
            CrossTenantGrantAuditEvents.GrantRemoved => "removed the grant of",
            _ => throw new ArgumentOutOfRangeException(nameof(eventName), eventName, "Not a grant event")
        };
        var message =
            $"'{actorName}' of tenant '{targetTenantId}' {verb} user '{mapping.SourceUserName}' of tenant '{mapping.SourceTenantId}' (mapping {mapping.RtId}, groups [{details["groupNames"]}])";

        return WriteAsync(eventName, warning: false, targetTenantId, mapping.SourceTenantId, message, details,
            sourceMustPermitTarget: true);
    }

    /// <inheritdoc />
    public async Task RecordFirstExchangeAsync(string targetTenantId, CrossTenantAuthResult source,
        string shadowUserName, RtExternalTenantUserMapping? mapping, IReadOnlyList<string> roles)
    {
        IReadOnlyList<string> groupNames = [];
        if (mapping != null)
        {
            try
            {
                groupNames = await groupStore.GetGroupNamesForExternalUserMappingAsync(mapping.RtId);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex,
                    "Cross-tenant audit: group names of mapping {MappingId} could not be read (AB#8342)", mapping.RtId);
            }
        }

        var details = new Dictionary<string, string>
        {
            ["actorTenantId"] = source.SourceTenantId,
            ["actorName"] = source.SourceUserName,
            ["sourceTenantId"] = source.SourceTenantId,
            ["targetTenantId"] = targetTenantId,
            ["sourceUserId"] = source.SourceUserId,
            ["sourceUserName"] = source.SourceUserName,
            ["shadowUserName"] = shadowUserName,
            ["mappingId"] = mapping?.RtId.ToString() ?? string.Empty,
            ["groupNames"] = string.Join(",", groupNames),
            ["roles"] = string.Join(",", roles)
        };
        var message =
            $"User '{source.SourceUserName}' of tenant '{source.SourceTenantId}' entered tenant '{targetTenantId}' for the first time as '{shadowUserName}' with roles [{details["roles"]}]";

        await WriteAsync(CrossTenantGrantAuditEvents.FirstExchange, warning: false, targetTenantId,
            source.SourceTenantId, message, details);
    }

    /// <inheritdoc />
    public async Task RecordExchangeRefusedAsync(string targetTenantId, string sourceTenantId, string sourceUserId,
        string reason)
    {
        try
        {
            if (string.Equals(targetTenantId, sourceTenantId, StringComparison.OrdinalIgnoreCase) ||
                (await ancestryGuard.GetRegistryAncestorsAsync(targetTenantId))
                .Contains(sourceTenantId, StringComparer.OrdinalIgnoreCase))
            {
                return;
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Cross-tenant audit: the ancestry of tenant {TargetTenantId} could not be read; the refused exchange is not recorded (AB#8342)",
                targetTenantId);
            return;
        }

        var details = new Dictionary<string, string>
        {
            ["actorTenantId"] = sourceTenantId,
            ["actorName"] = sourceUserId,
            ["sourceTenantId"] = sourceTenantId,
            ["targetTenantId"] = targetTenantId,
            ["sourceUserId"] = sourceUserId,
            ["reason"] = reason
        };
        var message =
            $"Token exchange of user '{sourceUserId}' of tenant '{sourceTenantId}' into tenant '{targetTenantId}' refused: {reason}";

        await WriteAsync(CrossTenantGrantAuditEvents.ExchangeRefused, warning: true, targetTenantId, sourceTenantId,
            message, details);
    }

    /// <summary>
    ///     Writes the event into T and — when <paramref name="sourceTenantId" /> names a registered tenant other than T —
    ///     into S. With <paramref name="sourceMustPermitTarget" /> S must also be a registry ancestor of T or permit T
    ///     (AB#8436). Each write is guarded on its own; nothing throws.
    /// </summary>
    private async Task WriteAsync(string eventName, bool warning, string targetTenantId, string? sourceTenantId,
        string message, IReadOnlyDictionary<string, string> details, bool sourceMustPermitTarget = false)
    {
        try
        {
            await StoreAsync(warning, targetTenantId, eventName, message, details);

            var source = await ResolveSourceTenantAsync(targetTenantId, sourceTenantId);
            if (source != null && sourceMustPermitTarget && !await SourceAdmitsTargetAsync(source, targetTenantId))
            {
                logger.LogInformation(
                    "Cross-tenant audit event {EventName} is recorded in target tenant {TargetTenantId} only: source tenant {SourceTenantId} is no registry ancestor and does not permit it (AB#8436)",
                    eventName, targetTenantId, source);
                source = null;
            }

            if (source != null)
            {
                await StoreAsync(warning, source, eventName, message, details);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Cross-tenant audit event {EventName} could not be recorded (AB#8342)", eventName);
        }
    }

    private Task StoreAsync(bool warning, string tenantId, string eventName, string message,
        IReadOnlyDictionary<string, string> details)
        => warning
            ? auditService.StoreWarningAsync(tenantId, eventName, message, details)
            : auditService.StoreInfoAsync(tenantId, eventName, message, details);

    /// <summary>
    ///     <c>true</c> when S is a registry ancestor of T or the grant policy says S permits T. Any failure answers
    ///     <c>false</c>: the event then stays in T, which is the safe side (AB#8436).
    /// </summary>
    private async Task<bool> SourceAdmitsTargetAsync(string sourceTenantId, string targetTenantId)
    {
        try
        {
            if ((await ancestryGuard.GetRegistryAncestorsAsync(targetTenantId))
                .Contains(sourceTenantId, StringComparer.OrdinalIgnoreCase))
            {
                return true;
            }

            return await grantPolicy.IsPermittedAsync(sourceTenantId, targetTenantId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Cross-tenant audit: could not decide whether source tenant {SourceTenantId} admits target tenant {TargetTenantId}; the event is recorded in the target tenant only (AB#8436)",
                sourceTenantId, targetTenantId);
            return false;
        }
    }

    /// <summary>The registered id of S, or <c>null</c> when S is empty, equals T or is not a registered tenant.</summary>
    private async Task<string?> ResolveSourceTenantAsync(string targetTenantId, string? sourceTenantId)
    {
        if (string.IsNullOrWhiteSpace(sourceTenantId) ||
            string.Equals(sourceTenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        try
        {
            return await tenantRegistry.TryGetRepositoryAsync(sourceTenantId) != null ? sourceTenantId : null;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Cross-tenant audit: the tenant registry could not be read for source tenant {SourceTenantId}; the event is recorded in the target tenant only (AB#8342)",
                sourceTenantId);
            return null;
        }
    }
}

/// <summary>
///     The audit hook of the source user lookup (AB#8341) — replaces <see cref="NoOpSourceUserLookupAuditSink" />.
/// </summary>
internal sealed class SourceUserLookupAuditSink(ICrossTenantGrantAuditRecorder recorder) : ISourceUserLookupAuditSink
{
    /// <inheritdoc />
    public Task RecordAsync(SourceUserLookupAuditEvent auditEvent, CancellationToken cancellationToken = default)
        => recorder.RecordLookupAsync(auditEvent);
}
