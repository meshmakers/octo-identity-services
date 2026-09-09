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

    /// <summary>
    ///     The client ids (<c>Client.ClientId</c>, not rtIds) of the clients holding a
    ///     <c>MayActAs</c> edge INTO the client <paramref name="targetClientRtId" /> — i.e. the
    ///     actors that may impersonate it. Direction-sensitive by construction: only inbound edges
    ///     count, so a client that is itself an actor for others never lists those targets here.
    ///     Empty for a client without inbound edges (and for an unknown rtId — the REST surface
    ///     answers 404 from the client lookup before consulting this).
    /// </summary>
    Task<IReadOnlyList<string>> GetActorClientIdsAsync(OctoObjectId targetClientRtId);
}
