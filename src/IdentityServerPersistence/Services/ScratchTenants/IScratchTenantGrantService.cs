using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence.Services.ScratchTenants;

/// <summary>Outcome of <see cref="IScratchTenantGrantService.EnsureGrantAsync" />.</summary>
public enum ScratchGrantStatus
{
    /// <summary>The tenant has no scratch marker; nothing was read or written in it.</summary>
    NotScratch,

    /// <summary>The grant was revoked earlier; it is never given again.</summary>
    Revoked,

    /// <summary>The marker names a parent that is not the tenant's actual parent (stale or foreign marker).</summary>
    ParentMismatch,

    /// <summary>
    ///     The creator's client has no mirror in the tenant (it is not flagged <c>AutoProvisionInChildTenants</c>, or
    ///     the mirror has not been provisioned yet) — nothing to grant to.
    /// </summary>
    MirrorMissing,

    /// <summary>The tenant has no <c>TenantOwners</c> group yet (identity defaults not seeded) — retried next time.</summary>
    GroupMissing,

    /// <summary>The creator's mirror already is a member of <c>TenantOwners</c>.</summary>
    AlreadyGranted,

    /// <summary>The creator's mirror was added to <c>TenantOwners</c> by this call.</summary>
    Granted
}

/// <summary>
///     The creator grant of a scratch tenant (AB#7192): the client-credentials client that created a tenant
///     with the opt-in <c>scratch</c> flag becomes administrator of it, so an agent can work in the tenant and clean it
///     up without a human login.
/// </summary>
/// <remarks>
///     <para>
///         The grant is the membership of the creator's <b>mirror</b> (the client record the parent's client has in the
///         child) in the child's <c>TenantOwners</c> group — exactly that one client, in exactly that one tenant. It is
///         derived from the <see cref="ScratchTenantMarker" /> in the system tenant's configuration, not stored as a
///         one-off edge: every tenant setup and every mirror (re)provisioning re-applies it, so it survives an identity
///         restart, a restore of the tenant and a re-provisioned mirror (whose edges are gone with the old record).
///     </para>
///     <para>
///         A revoke is persisted in the same marker. The re-sync reads it and does not grant again.
///     </para>
/// </remarks>
public interface IScratchTenantGrantService
{
    /// <summary>The scratch marker of <paramref name="childTenantId" />, or <c>null</c> when it is not a scratch tenant.</summary>
    Task<ScratchTenantMarker?> GetMarkerAsync(string childTenantId);

    /// <summary>
    ///     Gives the creator's mirror the <c>TenantOwners</c> group of the child, when the tenant has a marker that is not
    ///     revoked and names the tenant's actual parent. Idempotent; never throws for an expected state (see
    ///     <see cref="ScratchGrantStatus" />). Does not provision the mirror itself.
    /// </summary>
    Task<ScratchGrantStatus> EnsureGrantAsync(string childTenantId);

    /// <summary>
    ///     Persists the revocation when the removal of <paramref name="clientRtId" /> from the group
    ///     <paramref name="groupRtId" /> took the creator's access away: the group is <c>TenantOwners</c> and the client
    ///     is the creator's mirror. Returns <c>true</c> when a revoke was recorded (and audited); <c>false</c> for any
    ///     other removal.
    /// </summary>
    /// <param name="childTenantId">The scratch tenant the removal happened in.</param>
    /// <param name="groupRtId">The group the client was removed from.</param>
    /// <param name="clientRtId">The removed client's rtId.</param>
    /// <param name="revokedBy">Who revoked (user name or client id), for the audit trail.</param>
    Task<bool> RecordRevocationAsync(string childTenantId, OctoObjectId groupRtId, OctoObjectId clientRtId,
        string revokedBy);
}
