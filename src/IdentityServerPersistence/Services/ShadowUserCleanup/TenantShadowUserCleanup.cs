using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.ShadowUserCleanup;

/// <summary>Outcome of the cleanup in one tenant.</summary>
/// <param name="Deleted">rtIds of the users deleted (Apply only).</param>
/// <param name="NotDeleted">rtIds of candidates that were not deleted (changed in the meantime or the delete failed).</param>
internal sealed record ShadowUserCleanupTenantResult(
    string TenantId,
    ShadowUserCleanupMode Mode,
    IReadOnlyList<ShadowUserCleanupDecision> Decisions,
    IReadOnlyList<string> Deleted,
    IReadOnlyList<string> NotDeleted)
{
    public int CandidateCount => Decisions.Count(d => d.IsCandidate);
}

/// <summary>
///     AB#8305: plans and (in Apply) runs the cleanup of rights-less cross-tenant shadow users in one tenant. See
///     <see cref="ShadowUserCleanupPlanner" /> for the rule.
/// </summary>
/// <remarks>
///     DryRun and Apply read the same facts and log the same plan: every candidate (tenant, rtId, user name, creation
///     date), the skip reasons of every other <c>xt_</c> user and a summary. Apply then re-reads each candidate right
///     before deleting it and keeps it if it gained an association or direct-use data in the meantime; the delete runs
///     through the identity user store (<see cref="IUserStore{TUser}.DeleteAsync" />), never as a raw database delete,
///     and each deleted user gets one information event in the tenant's event log. A second Apply finds nothing.
/// </remarks>
internal static class TenantShadowUserCleanup
{
    /// <summary>Event name of the audit record written per deleted user.</summary>
    public const string AuditEventName = "Identity.ShadowUserDeleted";

    /// <summary>Reads the mapping sources of a tenant (used for the chain-source rule across tenants).</summary>
    public static async Task<IReadOnlyList<ShadowUserMappingSource>> ReadMappingSourcesAsync(ITenantRepository repository)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var mappings = await repository.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(
            session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return mappings.Items
            .Select(m => new ShadowUserMappingSource(m.SourceTenantId ?? string.Empty, m.SourceUserId ?? string.Empty,
                m.SourceUserName ?? string.Empty))
            .ToList();
    }

    public static async Task<ShadowUserCleanupTenantResult> RunAsync(
        string tenantId,
        ITenantRepository repository,
        ShadowUserCleanupMode mode,
        IReadOnlyCollection<ShadowUserMappingSource> mappingsInAllTenants,
        IUserStore<RtUser> userStore,
        Func<string, string, Task>? audit,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        if (mode == ShadowUserCleanupMode.Off)
        {
            return new ShadowUserCleanupTenantResult(tenantId, mode, [], [], []);
        }

        var mappingsInTenant = await ReadMappingSourcesAsync(repository);
        var facts = await ReadShadowUserFactsAsync(repository, null);
        var decisions = ShadowUserCleanupPlanner.Plan(tenantId, facts.Values.Select(f => f.Facts), mappingsInTenant, mappingsInAllTenants);

        foreach (var decision in decisions)
        {
            if (decision.IsCandidate)
            {
                logger.LogInformation(
                    "ShadowUserCleanup {Mode} tenant '{TenantId}': candidate rtId={RtId} userName={UserName} created={CreatedAt:o}",
                    mode, tenantId, decision.RtId, decision.UserName, decision.CreatedAt);
            }
            else
            {
                logger.LogInformation(
                    "ShadowUserCleanup {Mode} tenant '{TenantId}': kept rtId={RtId} userName={UserName} reasons={Reasons}",
                    mode, tenantId, decision.RtId, decision.UserName, string.Join(",", decision.SkipReasons));
            }
        }

        var candidates = decisions.Where(d => d.IsCandidate).ToList();
        var deleted = new List<string>();
        var notDeleted = new List<string>();

        if (mode == ShadowUserCleanupMode.Apply)
        {
            foreach (var candidate in candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (await TryDeleteAsync(candidate))
                {
                    deleted.Add(candidate.RtId);
                }
                else
                {
                    notDeleted.Add(candidate.RtId);
                }
            }
        }

        logger.LogInformation(
            "ShadowUserCleanup {Mode} tenant '{TenantId}': {ShadowUserCount} xt_ users, {CandidateCount} candidates, " +
            "{KeptCount} kept, {DeletedCount} deleted, {NotDeletedCount} candidates not deleted",
            mode, tenantId, decisions.Count, candidates.Count, decisions.Count - candidates.Count, deleted.Count,
            notDeleted.Count);

        return new ShadowUserCleanupTenantResult(tenantId, mode, decisions, deleted, notDeleted);

        async Task<bool> TryDeleteAsync(ShadowUserCleanupDecision candidate)
        {
            // Re-check right before the delete: a role, group, mapping or login granted since the plan keeps the user.
            var current = await ReadShadowUserFactsAsync(repository, candidate.RtId);
            if (!current.TryGetValue(candidate.RtId, out var user))
            {
                logger.LogInformation(
                    "ShadowUserCleanup Apply tenant '{TenantId}': rtId={RtId} no longer exists, nothing to delete",
                    tenantId, candidate.RtId);
                return false;
            }

            var recheck = ShadowUserCleanupPlanner.Plan(
                tenantId, [user.Facts], await ReadMappingSourcesAsync(repository), mappingsInAllTenants);
            if (recheck.Count != 1 || !recheck[0].IsCandidate)
            {
                logger.LogWarning(
                    "ShadowUserCleanup Apply tenant '{TenantId}': rtId={RtId} changed since the plan, kept ({Reasons})",
                    tenantId, candidate.RtId, recheck.Count == 1 ? string.Join(",", recheck[0].SkipReasons) : "not xt_");
                return false;
            }

            var result = await userStore.DeleteAsync(user.Entity, cancellationToken);
            if (!result.Succeeded)
            {
                logger.LogWarning(
                    "ShadowUserCleanup Apply tenant '{TenantId}': deleting rtId={RtId} failed: {Errors}",
                    tenantId, candidate.RtId, string.Join(", ", result.Errors.Select(e => e.Code)));
                return false;
            }

            logger.LogInformation(
                "ShadowUserCleanup Apply tenant '{TenantId}': deleted rtId={RtId} userName={UserName} created={CreatedAt:o}",
                tenantId, candidate.RtId, candidate.UserName, candidate.CreatedAt);

            if (audit != null)
            {
                try
                {
                    await audit(tenantId,
                        $"[{AuditEventName}] Deleted the rights-less cross-tenant shadow user '{candidate.UserName}' " +
                        $"(rtId {candidate.RtId}, created {candidate.CreatedAt:o}) by IdentityApiAuthorization:ShadowUserCleanup=Apply (AB#8305)");
                }
                catch (Exception ex)
                {
                    // Auditing never undoes the delete; the log line above is the fallback record.
                    logger.LogWarning(ex,
                        "ShadowUserCleanup Apply tenant '{TenantId}': audit event for rtId={RtId} could not be stored",
                        tenantId, candidate.RtId);
                }
            }

            return true;
        }
    }

    private sealed record LoadedShadowUser(RtUser Entity, ShadowUserFacts Facts);

    /// <summary>Reads the facts of all <c>xt_</c> users of the tenant, or of the one user <paramref name="onlyRtId" />.</summary>
    private static async Task<IReadOnlyDictionary<string, LoadedShadowUser>> ReadShadowUserFactsAsync(
        ITenantRepository repository, string? onlyRtId)
    {
        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();

        IEnumerable<RtUser> users;
        if (onlyRtId != null)
        {
            var single = await repository.GetRtEntityByRtIdAsync<RtUser>(session, new OctoObjectId(onlyRtId));
            users = single == null ? [] : [single];
        }
        else
        {
            // Users per tenant are few; filtering in memory avoids relying on a prefix operator of the query API.
            users = (await repository.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create())).Items;
        }

        var result = new Dictionary<string, LoadedShadowUser>(StringComparer.Ordinal);
        foreach (var user in users.Where(u => CrossTenantShadowUserName.IsShadowUserName(u.UserName)))
        {
            var rtId = user.RtId.ToString();
            var edges = await repository.GetRtAssociationsAsync(session,
                new RtEntityId(userCkTypeId, user.RtId),
                RtAssociationExtendedQueryOptions.Create(GraphDirections.Any));

            var directUse = new List<string>();
            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                directUse.Add("password");
            }

            if (user.TwoFactorEnabled)
            {
                directUse.Add("two-factor");
            }

            if (user.UserLogins is { Count: > 0 })
            {
                directUse.Add("external-login");
            }

            if (user.UserTokens is { Count: > 0 })
            {
                directUse.Add("user-token");
            }

            if (user.Claims is { Count: > 0 })
            {
                directUse.Add("claim");
            }

            var subject = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtOAuthToken.SubjectId), FieldFilterOperator.Equals, rtId);
            if ((await repository.GetRtEntitiesByTypeAsync<RtOAuthToken>(session, subject)).Items.Any())
            {
                directUse.Add("oauth-token");
            }

            var authorizationSubject = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtOAuthAuthorization.SubjectId), FieldFilterOperator.Equals, rtId);
            if ((await repository.GetRtEntitiesByTypeAsync<RtOAuthAuthorization>(session, authorizationSubject)).Items.Any())
            {
                directUse.Add("oauth-authorization");
            }

            result[rtId] = new LoadedShadowUser(user, new ShadowUserFacts(
                rtId,
                user.UserName!,
                user.RtCreationDateTime,
                edges.Items
                    .Select(e => new ShadowUserEdge(
                        Classify(e.AssociationRoleId), e.AssociationRoleId?.ToString() ?? "unknown"))
                    .ToList(),
                directUse));
        }

        await session.CommitTransactionAsync();
        return result;
    }

    private static ShadowUserEdgeKind Classify(RtCkId<CkAssociationRoleId>? roleId)
    {
        if (roleId == IdentityAssociationConstants.AssignedRoleId)
        {
            return ShadowUserEdgeKind.AssignedRole;
        }

        return roleId == IdentityAssociationConstants.GroupMemberId
            ? ShadowUserEdgeKind.GroupMember
            : ShadowUserEdgeKind.Other;
    }
}
