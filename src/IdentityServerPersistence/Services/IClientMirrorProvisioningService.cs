using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
/// Mirrors <c>ClientCredentials</c> clients with <c>AutoProvisionInChildTenants=true</c>
/// from a parent tenant into one or more child tenants and keeps the mirrors in sync.
/// </summary>
/// <remarks>
/// Used by:
/// <list type="bullet">
/// <item>The tenant lifecycle hook in <see cref="DefaultConfigurationCreatorService"/>
/// — every new child tenant gets mirrored on first setup, and also re-checked on each
/// startup (idempotent).</item>
/// <item>The <c>ClientStore</c> upkeep hooks — updates and deletes on a flagged client
/// fan out to every mirror.</item>
/// <item>The <c>PreDeleteTenant</c> consumer — drops tracking rows for a deleted tenant.</item>
/// <item>The backfill REST endpoint (issue #4045) — a one-shot provisioning into
/// every existing child of the parent.</item>
/// </list>
/// All operations are idempotent.
/// </remarks>
public interface IClientMirrorProvisioningService
{
    /// <summary>
    /// Walks every <c>Client</c> in <paramref name="parentTenantId"/> that has
    /// <c>AutoProvisionInChildTenants=true</c>, ensures a mirror exists in
    /// <paramref name="childTenantId"/>, and writes a <c>ClientMirror</c> tracking
    /// row in the parent tenant's DB.
    /// </summary>
    Task<ClientMirrorProvisioningResult> ProvisionForChildTenantAsync(
        string parentTenantId, string childTenantId);

    /// <summary>
    /// Propagates a parent-client mutation (secret rotation, scope / grant type / lifetime
    /// change, …) onto every mirror that exists for this client, then bumps each mirror's
    /// <c>SecretHashVersion</c>. No-op when the client has no mirrors.
    /// </summary>
    /// <remarks>
    /// Idempotent: replaying it produces the same end state, only with a higher version
    /// counter on each mirror. Failures on individual child tenants do not abort the loop —
    /// each failure is recorded in the result.
    /// </remarks>
    Task<ClientMirrorSyncResult> SyncMirrorsForClientAsync(
        string parentTenantId, RtClient parentClient);

    /// <summary>
    /// Removes every mirror (both the child-tenant client record and the parent's tracking
    /// row) for the given parent <c>ClientId</c>.
    /// </summary>
    Task<ClientMirrorCleanupResult> RemoveMirrorsForClientAsync(
        string parentTenantId, string parentClientId);

    /// <summary>
    /// Drops every tracking row in the parent that points at the deleted child tenant.
    /// The mirror clients themselves are gone with the tenant database, so no per-child
    /// cleanup is needed.
    /// </summary>
    /// <returns>The number of tracking rows that were removed.</returns>
    Task<int> RemoveMirrorsForChildTenantAsync(
        string parentTenantId, string childTenantId);

    /// <summary>
    /// Backfill: walks every child tenant of <paramref name="parentTenantId"/> and
    /// ensures a mirror of <paramref name="parentClientId"/> exists in each. The
    /// per-child work is delegated to <see cref="ProvisionForChildTenantAsync"/>, so
    /// other clients in the parent that are also flagged get backfilled at the same
    /// time — this is intentional (the operator's intent is "make every flagged
    /// client present everywhere it should be"), but it does mean the client-id
    /// argument is only used for the up-front "is this client flagged?" guard.
    /// Returns <c>null</c> if the named client either doesn't exist or isn't flagged.
    /// </summary>
    Task<ClientMirrorBackfillResult?> ProvisionForAllChildTenantsAsync(
        string parentTenantId, string parentClientId);

    /// <summary>
    /// Lists the tracking rows recorded in the parent's DB for a given client.
    /// Returns an empty list when the client has no mirrors.
    /// </summary>
    Task<IReadOnlyList<RtClientMirror>> GetMirrorsAsync(
        string parentTenantId, string parentClientId);

    /// <summary>
    /// Provisions a single (parentClientId × childTenantId) mirror. No-op if the
    /// mirror already exists (still returns success).
    /// </summary>
    Task<ClientMirrorProvisioningResult> ProvisionInTenantAsync(
        string parentTenantId, string parentClientId, string childTenantId);

    /// <summary>
    /// Removes a single mirror (drops the child-side <c>RtClient</c> and the
    /// parent's tracking row). Returns false if no mirror was tracked for that pair.
    /// </summary>
    Task<bool> RemoveMirrorAsync(
        string parentTenantId, string parentClientId, string childTenantId);
}

/// <summary>Summary of one provisioning run for telemetry / API responses.</summary>
public sealed record ClientMirrorProvisioningResult(
    int FlaggedClientsConsidered,
    int NewlyProvisioned,
    int AlreadyPresent);

/// <summary>Summary of one sync run.</summary>
public sealed record ClientMirrorSyncResult(
    int MirrorsSynced,
    int MirrorsFailed);

/// <summary>Summary of one cleanup run.</summary>
public sealed record ClientMirrorCleanupResult(
    int MirrorsRemoved,
    int MirrorsFailed);

/// <summary>Summary of a backfill across all child tenants.</summary>
public sealed record ClientMirrorBackfillResult(
    int ChildTenantsConsidered,
    int NewlyProvisioned,
    int AlreadyPresent);
