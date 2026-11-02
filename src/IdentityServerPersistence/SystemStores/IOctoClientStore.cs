using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     CRUD + query store for OAuth clients over the per-tenant <see cref="RtClient" /> CK
///     entities, including the client-mirror upkeep hooks. Management-plane only since
///     AB#4989/AB#4996 — protocol reads go through
///     <see cref="OpenIddict.OpenIddictApplicationStore" />.
/// </summary>
public interface IOctoClientStore
{
    public string TenantId { get; }

    Task<IEnumerable<RtClient>> GetClients();

    Task CreateAsync(RtClient client);

    /// <summary>
    ///     Changes the stored client as one version-checked read-modify-write (AB#7989): a concurrent write is never lost
    ///     and never brings back what this change removed. <paramref name="mutate" /> returns <c>false</c> to write nothing
    ///     and can run more than once (on a conflict it gets a fresh read). After a write the mirrors of a flagged client are
    ///     synced (best effort: a failure is logged, never thrown). This is the only way to change a stored client (AB#8015):
    ///     there is no unversioned replace, so every write advances <c>rtVersion</c> and the version checks of the other
    ///     writers (client mirror reconciliation, AB#8019/AB#8054) see it.
    /// </summary>
    /// <returns>The client as stored; <c>null</c> when it does not exist.</returns>
    Task<RtClient?> MutateAsync(string clientId, Func<RtClient, bool> mutate);

    Task DeleteAsync(string clientId);

    /// <summary>
    ///     Finds a client by id
    /// </summary>
    /// <param name="clientId">The client id</param>
    /// <returns>The client</returns>
    Task<RtClient?> FindRtClientByIdAsync(string clientId);
}
