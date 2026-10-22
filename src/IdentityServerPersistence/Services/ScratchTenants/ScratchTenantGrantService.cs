using System.Collections.Concurrent;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.ScratchTenants;

/// <inheritdoc cref="IScratchTenantGrantService" />
public class ScratchTenantGrantService(
    ILogger<ScratchTenantGrantService> logger,
    ISystemContext systemContext,
    IEventRepository? eventRepository = null) : IScratchTenantGrantService
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    public async Task<ScratchTenantMarker?> GetMarkerAsync(string childTenantId)
    {
        if (string.IsNullOrWhiteSpace(childTenantId) ||
            string.Equals(childTenantId, systemContext.TenantId, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        using var session = await systemContext.GetAdminSessionAsync();
        return await systemContext.GetConfigurationAsync<ScratchTenantMarker>(
            session, ScratchTenantMarker.GetConfigurationKey(childTenantId), defaultValue: null);
    }

    public async Task<ScratchGrantStatus> EnsureGrantAsync(string childTenantId)
    {
        var marker = await GetMarkerAsync(childTenantId);
        if (marker == null)
        {
            return ScratchGrantStatus.NotScratch;
        }

        // Serialises the runs inside this process (setup, tenant update and mirror provisioning reach the same tenant at
        // the same moment). Several replicas can still race; the second identical GroupMember edge is harmless (group
        // membership is read as a set) and the re-read right before the insert keeps it rare.
        var gate = Locks.GetOrAdd(childTenantId.Trim().ToLowerInvariant(), _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            // Re-read under the lock: a revoke may have been recorded while this call waited.
            marker = await GetMarkerAsync(childTenantId);
            return marker == null ? ScratchGrantStatus.NotScratch : await EnsureGrantCoreAsync(childTenantId, marker);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<ScratchGrantStatus> EnsureGrantCoreAsync(string childTenantId, ScratchTenantMarker marker)
    {
        if (marker.RevokedAtUtc != null)
        {
            logger.LogDebug("Scratch creator grant of tenant '{TenantId}' is revoked; not granting again", childTenantId);
            return ScratchGrantStatus.Revoked;
        }

        if (!await IsParentOfAsync(marker.ParentTenantId, childTenantId))
        {
            logger.LogWarning(
                "Scratch marker of tenant '{TenantId}' names parent '{ParentTenantId}', which is not the tenant's " +
                "parent; no grant is given (AB#7192)", childTenantId, marker.ParentTenantId);
            return ScratchGrantStatus.ParentMismatch;
        }

        var childContext = await systemContext.TryFindTenantContextAsync(childTenantId);
        if (childContext == null)
        {
            return ScratchGrantStatus.MirrorMissing;
        }

        var repository = childContext.GetTenantRepositoryAsAdmin();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var mirror = await FindCreatorMirrorAsync(repository, session, marker);
        if (mirror == null)
        {
            await session.CommitTransactionAsync();
            logger.LogWarning(
                "Scratch tenant '{TenantId}': the creator client '{ClientId}' has no mirror from tenant " +
                "'{ParentTenantId}' there, so it cannot become administrator. The client has to be flagged " +
                "AutoProvisionInChildTenants (AB#7192)", childTenantId, marker.CreatorClientId, marker.ParentTenantId);
            return ScratchGrantStatus.MirrorMissing;
        }

        var group = await FindTenantOwnersGroupAsync(repository, session);
        if (group == null)
        {
            await session.CommitTransactionAsync();
            logger.LogInformation(
                "Scratch tenant '{TenantId}' has no {Group} group yet; the grant is retried on the next setup",
                childTenantId, CommonConstants.TenantOwnersGroup);
            return ScratchGrantStatus.GroupMissing;
        }

        var groupEntityId = group.ToRtEntityId();
        var clientEntityId = mirror.ToRtEntityId();
        var existing = await repository.GetRtAssociationOrDefaultAsync(
            session, groupEntityId, clientEntityId, IdentityAssociationConstants.GroupMemberId);
        if (existing != null)
        {
            await session.CommitTransactionAsync();
            return ScratchGrantStatus.AlreadyGranted;
        }

        var opResult = new OperationResult();
        await repository.ApplyChangesAsync(session,
            [AssociationUpdateInfo.CreateInsert(groupEntityId, clientEntityId, IdentityAssociationConstants.GroupMemberId)],
            opResult);
        if (opResult.HasErrors || opResult.HasFatalErrors)
        {
            await session.AbortTransactionAsync();
            throw new InvalidOperationException(
                $"Failed to add client '{marker.CreatorClientId}' to {CommonConstants.TenantOwnersGroup} of scratch tenant " +
                $"'{childTenantId}': {string.Join("; ", opResult.GetMessages())}");
        }

        await session.CommitTransactionAsync();

        await OnMembershipInsertedAsync(childTenantId);

        // A revoke on another replica persists the marker first and then removes the membership; if that removal ran
        // before the insert above, nothing was there to remove. Look at the marker once more after the insert and take
        // the edge out again when the revoke has been recorded meanwhile, so the two orders end in the same state.
        var current = await GetMarkerAsync(childTenantId);
        if (current?.RevokedAtUtc != null)
        {
            await RemoveMembershipAsync(repository, groupEntityId, clientEntityId);
            logger.LogWarning(
                "Scratch tenant '{TenantId}': the creator grant was revoked while it was being applied; the membership " +
                "was removed again (AB#7192)", childTenantId);
            return ScratchGrantStatus.Revoked;
        }

        if (marker.GrantedAtUtc == null)
        {
            // The timestamp goes onto the freshest copy of the marker, never onto the one read at the start of the run:
            // saving that one would write over a revoke recorded since.
            await OnBeforeGrantTimestampSavedAsync(childTenantId);
            var latest = await GetMarkerAsync(childTenantId);
            if (latest?.RevokedAtUtc != null)
            {
                await RemoveMembershipAsync(repository, groupEntityId, clientEntityId);
                logger.LogWarning(
                    "Scratch tenant '{TenantId}': the creator grant was revoked while it was being applied; the " +
                    "membership was removed again (AB#7192)", childTenantId);
                return ScratchGrantStatus.Revoked;
            }

            if (latest != null)
            {
                latest.GrantedAtUtc ??= DateTime.UtcNow;
                marker = latest;
                await SaveMarkerAsync(childTenantId, latest);
            }
        }

        await AuditAsync(childTenantId,
            $"Scratch tenant creator access granted: client '{marker.CreatorClientId}' (mirror of tenant " +
            $"'{marker.ParentTenantId}', created {marker.CreatedAtUtc:O}) is a member of {CommonConstants.TenantOwnersGroup} " +
            $"in tenant '{childTenantId}'");
        return ScratchGrantStatus.Granted;
    }

    /// <summary>
    ///     Called right after the membership was committed and before the marker is checked for a revoke that another
    ///     replica recorded meanwhile. A seam for tests that have to interleave that revoke deterministically.
    /// </summary>
    protected virtual Task OnMembershipInsertedAsync(string childTenantId) => Task.CompletedTask;

    /// <summary>Test seam like <see cref="OnMembershipInsertedAsync" />, just before the grant timestamp is written.</summary>
    protected virtual Task OnBeforeGrantTimestampSavedAsync(string childTenantId) => Task.CompletedTask;

    private static async Task RemoveMembershipAsync(ITenantRepository repository, RtEntityId groupEntityId,
        RtEntityId clientEntityId)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var opResult = new OperationResult();
        await repository.ApplyChangesAsync(session,
            [AssociationUpdateInfo.CreateDelete(groupEntityId, clientEntityId, IdentityAssociationConstants.GroupMemberId)],
            opResult);
        if (opResult.HasErrors || opResult.HasFatalErrors)
        {
            await session.AbortTransactionAsync();
            throw new InvalidOperationException(
                $"Failed to remove a revoked scratch creator from {CommonConstants.TenantOwnersGroup}: " +
                string.Join("; ", opResult.GetMessages()));
        }

        await session.CommitTransactionAsync();
    }

    public async Task<bool> RecordRevocationAsync(string childTenantId, OctoObjectId groupRtId,
        OctoObjectId clientRtId, string revokedBy)
    {
        var marker = await GetMarkerAsync(childTenantId);
        if (marker == null || marker.RevokedAtUtc != null)
        {
            return false;
        }

        var childContext = await systemContext.TryFindTenantContextAsync(childTenantId);
        if (childContext == null)
        {
            return false;
        }

        var repository = childContext.GetTenantRepositoryAsAdmin();
        using (var session = await repository.GetSessionAsync())
        {
            var group = await repository.GetRtEntityByRtIdAsync<RtGroup>(session, groupRtId);
            if (group == null || !IsTenantOwners(group))
            {
                return false;
            }

            var client = await repository.GetRtEntityByRtIdAsync<RtClient>(session, clientRtId);
            if (client == null || !IsCreatorMirror(client, marker))
            {
                return false;
            }
        }

        var gate = Locks.GetOrAdd(childTenantId.Trim().ToLowerInvariant(), _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            marker = await GetMarkerAsync(childTenantId);
            if (marker == null || marker.RevokedAtUtc != null)
            {
                return false;
            }

            marker.RevokedAtUtc = DateTime.UtcNow;
            marker.RevokedBy = revokedBy;
            await SaveMarkerAsync(childTenantId, marker);
        }
        finally
        {
            gate.Release();
        }

        await AuditAsync(childTenantId,
            $"Scratch tenant creator access revoked: client '{marker.CreatorClientId}' was removed from " +
            $"{CommonConstants.TenantOwnersGroup} of tenant '{childTenantId}' by '{revokedBy}'. The tenant setup does " +
            "not grant it again");
        return true;
    }

    private async Task<bool> IsParentOfAsync(string parentTenantId, string childTenantId)
    {
        if (string.IsNullOrWhiteSpace(parentTenantId))
        {
            return false;
        }

        // Fresh registry read (not the cached ITenantRegistry snapshot): a scratch tenant is set up the moment it is
        // created, and a snapshot taken a second earlier does not know it yet.
        using var session = await systemContext.GetAdminSessionAsync();
        var all = await systemContext.GetAllTenantsAsync(session);
        var tenant = all.Items.FirstOrDefault(t =>
            string.Equals(t.TenantId, childTenantId, StringComparison.OrdinalIgnoreCase));
        if (tenant == null)
        {
            return false;
        }

        // A registry record without a parent id is a direct child of the registry owner, the system tenant.
        var actualParent = string.IsNullOrEmpty(tenant.ParentTenantId) ? systemContext.TenantId : tenant.ParentTenantId;
        return string.Equals(actualParent, parentTenantId, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<RtClient?> FindCreatorMirrorAsync(ITenantRepository repository, IOctoSession session,
        ScratchTenantMarker marker)
    {
        var clients = await repository.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, marker.CreatorClientId));
        return clients.Items.FirstOrDefault(c => IsCreatorMirror(c, marker));
    }

    /// <summary>
    ///     Only the mirror counts: a client of the same id that someone created in the child (or that came with a
    ///     restored dump) carries no <c>ProvisionedByParentTenantId</c> of the creator's parent and is never granted.
    /// </summary>
    private static bool IsCreatorMirror(RtClient client, ScratchTenantMarker marker)
    {
        return string.Equals(client.ClientId, marker.CreatorClientId, StringComparison.Ordinal) &&
               string.Equals(client.ProvisionedByParentTenantId, marker.ParentTenantId,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTenantOwners(RtGroup group)
    {
        return string.Equals(group.NormalizedGroupName, CommonConstants.TenantOwnersGroup.ToUpperInvariant(),
            StringComparison.Ordinal);
    }

    private static async Task<RtGroup?> FindTenantOwnersGroupAsync(ITenantRepository repository, IOctoSession session)
    {
        var groups = await repository.GetRtEntitiesByTypeAsync<RtGroup>(session,
            RtEntityQueryOptions.Create().FieldEquals(nameof(RtGroup.NormalizedGroupName),
                CommonConstants.TenantOwnersGroup.ToUpperInvariant()));
        return groups.Items.FirstOrDefault();
    }

    private async Task SaveMarkerAsync(string childTenantId, ScratchTenantMarker marker)
    {
        using var session = await systemContext.GetAdminSessionAsync();
        await systemContext.SetConfigurationAsync(session, ScratchTenantMarker.GetConfigurationKey(childTenantId),
            marker);
    }

    /// <summary>
    ///     The audit trail of grant and revoke: an information event in the tenant's own event log and one in the system
    ///     tenant's, which outlives the tenant. Auditing never breaks the grant itself.
    /// </summary>
    private async Task AuditAsync(string childTenantId, string message)
    {
        logger.LogInformation("{Message}", message);
        if (eventRepository == null)
        {
            return;
        }

        try
        {
            await eventRepository.StoreSystemInformationEvent(RtEventSourcesEnum.IdentityService, message);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to persist the scratch-tenant audit event to the system event log");
        }

        try
        {
            await eventRepository.StoreInformationEvent(childTenantId, RtEventSourcesEnum.IdentityService, message);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to persist the scratch-tenant audit event to the event log of tenant " +
                                  "'{TenantId}'", childTenantId);
        }
    }
}
