using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using IdentityServerPersistence.SystemStores;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using OpenIddictStatuses = OpenIddict.Abstractions.OpenIddictConstants.Statuses;

namespace IdentityServerPersistence.Services.ShadowUserCleanup;

/// <summary>Outcome of the cleanup in one tenant.</summary>
/// <param name="Deleted">rtIds of the users deleted (Apply only).</param>
/// <param name="NotDeleted">rtIds of candidates that were not deleted (changed in the meantime or the delete failed).</param>
/// <param name="DeletedMappings">rtIds of the empty mappings deleted together with their users (Apply only).</param>
internal sealed record ShadowUserCleanupTenantResult(
    string TenantId,
    ShadowUserCleanupMode Mode,
    IReadOnlyList<ShadowUserCleanupDecision> Decisions,
    IReadOnlyList<string> Deleted,
    IReadOnlyList<string> NotDeleted,
    IReadOnlyList<string> DeletedMappings)
{
    public int CandidateCount => Decisions.Count(d => d.IsCandidate);
}

/// <summary>
///     AB#8305: plans and (in Apply) runs the cleanup of rights-less cross-tenant shadow users in one tenant. See
///     <see cref="ShadowUserCleanupPlanner" /> for the rule.
/// </summary>
/// <remarks>
///     DryRun and Apply read the same facts and log the same plan: every candidate (tenant, rtId, user name, creation
///     date, the empty mappings and the OAuth tokens and authorizations that go with it), the skip reasons of every other
///     <c>xt_</c> user and a summary. Apply then re-reads each candidate right before deleting it and keeps it if it
///     gained an association, a role-granting mapping or direct-use data in the meantime. For a candidate it then
///     (1) revokes its OAuth tokens and authorizations through the OpenIddict stores, (2) deletes its empty mappings
///     (rule A) and (3) deletes the user through the identity user store
///     (<see cref="IUserStore{TUser}.DeleteAsync" />), never as a raw user delete. Each deleted user gets one information
///     event in the tenant's event log that also names the deleted mapping ids. A second Apply finds nothing.
/// </remarks>
internal static class TenantShadowUserCleanup
{
    /// <summary>Event name of the audit record written per deleted user.</summary>
    public const string AuditEventName = "Identity.ShadowUserDeleted";

    /// <summary>
    ///     Reads the mappings of the tenant the users live in, with their rtId and whether each actually grants a role
    ///     (rule A): a non-empty <c>MappedRoleIds</c> list, a <c>GroupMember</c> edge from a group that holds a role
    ///     (directly or through its child groups, as <see cref="GroupRoleResolver" /> resolves it at token time), or any
    ///     other association, which is kept to err on the safe side.
    /// </summary>
    public static async Task<IReadOnlyList<ShadowUserMappingSource>> ReadTenantMappingsAsync(ITenantRepository repository)
    {
        var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
        var mappings = new List<(RtExternalTenantUserMapping Mapping, bool OtherAssociation, List<OctoObjectId> Groups)>();
        using (var session = await repository.GetSessionAsync())
        {
            session.StartTransaction();
            var items = await repository.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(
                session, RtEntityQueryOptions.Create());
            foreach (var mapping in items.Items)
            {
                var edges = await repository.GetRtAssociationsAsync(session, mapping.ToRtEntityId(),
                    RtAssociationExtendedQueryOptions.Create(GraphDirections.Any));
                var groups = new List<OctoObjectId>();
                var other = false;
                foreach (var edge in edges.Items)
                {
                    if (edge.AssociationRoleId == IdentityAssociationConstants.GroupMemberId
                        && edge.OriginCkTypeId == groupCkTypeId
                        && edge.TargetRtId == mapping.RtId)
                    {
                        groups.Add(edge.OriginRtId);
                    }
                    else
                    {
                        other = true;
                    }
                }

                mappings.Add((mapping, other, groups));
            }

            await session.CommitTransactionAsync();
        }

        var groupStore = new GroupStore(new ShadowUserCleanupTenantResolver(repository));
        var groupGrantsRole = new Dictionary<OctoObjectId, bool>();
        var result = new List<ShadowUserMappingSource>();
        foreach (var (mapping, other, groups) in mappings)
        {
            var grants = other || mapping.MappedRoleIds is { Count: > 0 };
            foreach (var groupId in groups)
            {
                if (grants)
                {
                    break;
                }

                if (!groupGrantsRole.TryGetValue(groupId, out var groupGrants))
                {
                    groupGrants = await GroupHoldsARoleAsync(groupStore, groupId, [], 0);
                    groupGrantsRole[groupId] = groupGrants;
                }

                grants = groupGrants;
            }

            result.Add(new ShadowUserMappingSource(mapping.SourceTenantId ?? string.Empty,
                mapping.SourceUserId ?? string.Empty, mapping.SourceUserName ?? string.Empty, mapping.RtId.ToString(),
                grants));
        }

        return result;
    }

    /// <summary>
    ///     True when the group or one of its child groups holds a role — the same walk as
    ///     <see cref="GroupRoleResolver" /> (ChildGroup edges, depth 10, cycles ignored).
    /// </summary>
    private static async Task<bool> GroupHoldsARoleAsync(
        IGroupStore groupStore, OctoObjectId groupId, HashSet<OctoObjectId> visited, int depth)
    {
        if (depth >= 10 || !visited.Add(groupId))
        {
            return false;
        }

        if ((await groupStore.GetRoleIdsAsync(groupId)).Count > 0)
        {
            return true;
        }

        foreach (var child in await groupStore.GetMemberGroupIdsAsync(groupId))
        {
            if (await GroupHoldsARoleAsync(groupStore, new OctoObjectId(child), visited, depth + 1))
            {
                return true;
            }
        }

        return false;
    }

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
            return new ShadowUserCleanupTenantResult(tenantId, mode, [], [], [], []);
        }

        var mappingsInTenant = await ReadTenantMappingsAsync(repository);
        var facts = await ReadShadowUserFactsAsync(repository, null);
        var decisions = ShadowUserCleanupPlanner.Plan(tenantId, facts.Values.Select(f => f.Facts), mappingsInTenant, mappingsInAllTenants);

        foreach (var decision in decisions)
        {
            if (decision.IsCandidate)
            {
                logger.LogInformation(
                    "ShadowUserCleanup {Mode} tenant '{TenantId}': candidate rtId={RtId} userName={UserName} created={CreatedAt:o} " +
                    "emptyMappings={EmptyMappings} oauthTokens={ActiveTokens} valid/{InactiveTokens} inactive " +
                    "oauthAuthorizations={ActiveAuthorizations} valid/{InactiveAuthorizations} inactive",
                    mode, tenantId, decision.RtId, decision.UserName, decision.CreatedAt,
                    decision.EmptyMappingIds.Count == 0 ? "none" : string.Join(",", decision.EmptyMappingIds),
                    decision.OAuth.ActiveTokens, decision.OAuth.InactiveTokens, decision.OAuth.ActiveAuthorizations,
                    decision.OAuth.InactiveAuthorizations);
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
        var deletedMappings = new List<string>();

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
            "{KeptCount} kept, {DeletedCount} deleted, {NotDeletedCount} candidates not deleted, " +
            "{EmptyMappingCount} empty mappings planned, {DeletedMappingCount} deleted",
            mode, tenantId, decisions.Count, candidates.Count, decisions.Count - candidates.Count, deleted.Count,
            notDeleted.Count, candidates.Sum(c => c.EmptyMappingIds.Count), deletedMappings.Count);

        return new ShadowUserCleanupTenantResult(tenantId, mode, decisions, deleted, notDeleted, deletedMappings);

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
                tenantId, [user.Facts], await ReadTenantMappingsAsync(repository), mappingsInAllTenants);
            if (recheck.Count != 1 || !recheck[0].IsCandidate)
            {
                logger.LogWarning(
                    "ShadowUserCleanup Apply tenant '{TenantId}': rtId={RtId} changed since the plan, kept ({Reasons})",
                    tenantId, candidate.RtId, recheck.Count == 1 ? string.Join(",", recheck[0].SkipReasons) : "not xt_");
                return false;
            }

            // Only mappings that are empty now AND were empty and unshared in the tenant-wide plan: a mapping that also
            // belongs to a kept user is never in the plan's list.
            var mappingIds = recheck[0].EmptyMappingIds
                .Intersect(candidate.EmptyMappingIds, StringComparer.Ordinal)
                .ToList();

            // (1) A token cannot carry a role the user cannot obtain; it goes with the user. Revoke first, so a failure
            // later never leaves a valid refresh token behind.
            var resolver = new ShadowUserCleanupTenantResolver(repository);
            var (revokedTokens, revokedAuthorizations) = await new UserTokenRevocation(
                    new OpenIddictTokenStore(resolver), new OpenIddictAuthorizationStore(resolver))
                .RevokeAllAsync(candidate.RtId, cancellationToken);

            // (2) The empty mappings: an empty mapping grants nothing, but counts as explicit provisioning for an
            // interactive sign-in, so it must not outlive its user.
            if (mappingIds.Count > 0)
            {
                try
                {
                    using var session = await repository.GetSessionAsync();
                    session.StartTransaction();
                    foreach (var mappingId in mappingIds)
                    {
                        await repository.DeleteOneRtEntityByRtIdAsync<RtExternalTenantUserMapping>(
                            session, new OctoObjectId(mappingId), DeleteOptions.Erase);
                    }

                    await session.CommitTransactionAsync();
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex,
                        "ShadowUserCleanup Apply tenant '{TenantId}': deleting the empty mappings {MappingIds} of " +
                        "rtId={RtId} failed; the user is kept", tenantId, string.Join(",", mappingIds), candidate.RtId);
                    return false;
                }
            }

            // (3) The user.
            var result = await userStore.DeleteAsync(user.Entity, cancellationToken);
            if (!result.Succeeded)
            {
                logger.LogWarning(
                    "ShadowUserCleanup Apply tenant '{TenantId}': deleting rtId={RtId} failed: {Errors}",
                    tenantId, candidate.RtId, string.Join(", ", result.Errors.Select(e => e.Code)));
                return false;
            }

            deletedMappings.AddRange(mappingIds);
            var mappingText = mappingIds.Count == 0 ? "none" : string.Join(",", mappingIds);
            logger.LogInformation(
                "ShadowUserCleanup Apply tenant '{TenantId}': deleted rtId={RtId} userName={UserName} created={CreatedAt:o} " +
                "emptyMappings={MappingIds} revokedTokens={RevokedTokens} revokedAuthorizations={RevokedAuthorizations}",
                tenantId, candidate.RtId, candidate.UserName, candidate.CreatedAt, mappingText, revokedTokens,
                revokedAuthorizations);

            if (audit != null)
            {
                try
                {
                    await audit(tenantId,
                        $"[{AuditEventName}] Deleted the rights-less cross-tenant shadow user '{candidate.UserName}' " +
                        $"(rtId {candidate.RtId}, created {candidate.CreatedAt:o}; deleted empty mappings: {mappingText}; " +
                        $"revoked {revokedTokens} OAuth token(s) and {revokedAuthorizations} authorization(s)) " +
                        "by IdentityApiAuthorization:ShadowUserCleanup=Apply (AB#8305)");
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

            // Rule A: OAuth tokens and authorizations never keep the user; they are counted for the log and revoked
            // together with the user in Apply.
            var now = DateTime.UtcNow;
            var subject = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtOAuthToken.SubjectId), FieldFilterOperator.Equals, rtId);
            var tokens = (await repository.GetRtEntitiesByTypeAsync<RtOAuthToken>(session, subject)).Items.ToList();
            var activeTokens = tokens.Count(t =>
                string.Equals(t.Status, OpenIddictStatuses.Valid, StringComparison.Ordinal)
                && (t.ExpirationDateTime == null || t.ExpirationDateTime.Value > now));

            var authorizationSubject = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtOAuthAuthorization.SubjectId), FieldFilterOperator.Equals, rtId);
            var authorizations = (await repository.GetRtEntitiesByTypeAsync<RtOAuthAuthorization>(
                session, authorizationSubject)).Items.ToList();
            var activeAuthorizations = authorizations.Count(a =>
                string.Equals(a.Status, OpenIddictStatuses.Valid, StringComparison.Ordinal));

            result[rtId] = new LoadedShadowUser(user, new ShadowUserFacts(
                rtId,
                user.UserName!,
                user.RtCreationDateTime,
                edges.Items
                    .Select(e => new ShadowUserEdge(
                        Classify(e.AssociationRoleId), e.AssociationRoleId?.ToString() ?? "unknown"))
                    .ToList(),
                directUse,
                new ShadowUserOAuthUse(activeTokens, tokens.Count - activeTokens, activeAuthorizations,
                    authorizations.Count - activeAuthorizations)));
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
