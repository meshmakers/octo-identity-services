using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Read access to the <c>System.Identity/MayActAs</c> edges between two <c>Client</c> entities
///     (AB#5114): the origin client may impersonate the target client via the impersonation grant,
///     and may delegate through it via the on-behalf-of <c>requested_client_id</c> extension.
/// </summary>
/// <remarks>
///     Deliberately a separate, minimal store: the edge is the whole authorization model of the
///     impersonation grant, so the check must stay trivially auditable — and substitutable in the
///     unit suite without dragging the repository API into every resolver test.
/// </remarks>
public interface IClientImpersonationStore
{
    /// <summary>
    ///     True when a <c>MayActAs</c> association from <paramref name="actorClientRtId" /> to
    ///     <paramref name="targetClientRtId" /> exists in the current request tenant.
    /// </summary>
    Task<bool> HasMayActAsEdgeAsync(OctoObjectId actorClientRtId, OctoObjectId targetClientRtId);
}
