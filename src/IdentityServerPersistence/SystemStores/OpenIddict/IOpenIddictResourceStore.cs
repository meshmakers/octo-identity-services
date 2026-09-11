using System.Collections.Immutable;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     Lookup store for the resource indicators (RFC 8707) a client may request, projecting the
///     per-tenant <c>RtApiResource</c> entities (AB#5193).
/// </summary>
/// <remarks>
///     <para>
///         OpenIddict 7.x ships no resource store and no resource manager: its
///         <c>ValidateResources</c> handlers compare the requested <c>resource</c> parameters
///         against <c>OpenIddictServerOptions.Resources</c> only, a static allow-list fed by
///         <c>RegisterResources(...)</c> at composition time. That list cannot express per-tenant
///         resources, so the OpenIddict 8.x line replaces it with a store-backed lookup
///         (<c>IOpenIddictResourceStore&lt;TResource&gt;</c> behind
///         <c>IOpenIddictResourceManager</c>). This interface is the same seam, ahead of time:
///         its members mirror the subset of the 8.x store the validation actually uses, and the
///         handlers in <c>Meshmakers.Octo.Backend.IdentityServices.OpenIddict</c> consume it
///         directly instead of going through a manager.
///     </para>
///     <para>
///         On the 8.x upgrade this interface and those handlers are deleted and the implementation
///         is registered with <c>ReplaceResourceStore&lt;RtApiResource, OpenIddictResourceStore&gt;()</c>,
///         next to the four stores already wired that way.
///     </para>
///     <para>
///         Two semantics sit in the store rather than in the handlers, so callers cannot forget
///         them: only <b>enabled</b> resources are returned (a disabled API resource must not be
///         requestable, mirroring <see cref="OpenIddictScopeStore" />), and lookups are
///         <b>trailing-slash insensitive</b> (see <see cref="ResourceIdentifiers" />).
///     </para>
/// </remarks>
/// <typeparam name="TResource">The API resource entity type.</typeparam>
public interface IOpenIddictResourceStore<TResource> where TResource : class
{
    /// <summary>Resolves a single enabled resource by its identifier, or <c>null</c>.</summary>
    ValueTask<TResource?> FindByNameAsync(string name, CancellationToken cancellationToken);

    /// <summary>
    ///     Resolves the enabled resources among <paramref name="names" /> in one round trip.
    ///     Unknown and disabled names are absent from the result — the caller decides what that means.
    /// </summary>
    IAsyncEnumerable<TResource> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken);

    /// <summary>Returns the resource identifier as stored (which may differ from the requested spelling).</summary>
    ValueTask<string?> GetNameAsync(TResource resource, CancellationToken cancellationToken);
}
