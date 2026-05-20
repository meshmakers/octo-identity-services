namespace IdentityServerPersistence.Services;

/// <summary>
/// Mirrors <c>ClientCredentials</c> clients with <c>AutoProvisionInChildTenants=true</c>
/// from a parent tenant into one or more child tenants.
/// </summary>
/// <remarks>
/// Used by:
/// <list type="bullet">
/// <item>The tenant lifecycle hook in <see cref="DefaultConfigurationCreatorService"/>
/// — every new child tenant gets mirrored on first setup, and also re-checked on each
/// startup (idempotent).</item>
/// <item>The backfill REST endpoint (issue #4045) — a one-shot provisioning into
/// every existing child of the parent.</item>
/// </list>
/// All operations are idempotent: provisioning twice produces no duplicate clients
/// and no duplicate mirror rows (the unique index on
/// <c>ClientMirror.(ParentClientId, ChildTenantId)</c> would reject the second insert anyway).
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
}

/// <summary>
/// Summary of one provisioning run for telemetry / API responses.
/// </summary>
public sealed record ClientMirrorProvisioningResult(
    int FlaggedClientsConsidered,
    int NewlyProvisioned,
    int AlreadyPresent);
