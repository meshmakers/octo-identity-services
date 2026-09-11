using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     <see cref="IOpenIddictResourceStore{TResource}" /> over the per-tenant
///     <see cref="RtApiResource" /> entities (AB#5193). Tenant scoping is inherited from
///     <see cref="IOctoResourceStore" />, which resolves the repository of the request tenant —
///     a resource registered in one tenant is invisible to every other one.
/// </summary>
/// <remarks>
///     Read-only by design: API resource CRUD belongs to <see cref="IOctoResourceStore" />
///     (TenantApi controllers, blueprint seeding), same split as
///     <see cref="OpenIddictScopeStore" />. There is no cache — entity caching is switched off
///     process-wide (tenant isolation, see <c>OpenIddictConfiguration</c>), so a resource created
///     or disabled through either path takes effect on the next request without an invalidation
///     round trip.
/// </remarks>
public class OpenIddictResourceStore(IOctoResourceStore resourceStore) : IOpenIddictResourceStore<RtApiResource>
{
    public async ValueTask<RtApiResource?> FindByNameAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        await foreach (var resource in FindByNamesAsync([name], cancellationToken))
        {
            return resource;
        }

        return null;
    }

    public async IAsyncEnumerable<RtApiResource> FindByNamesAsync(
        ImmutableArray<string> names,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // One query for all requested indicators, each expanded into its slash variants.
        var candidates = names
            .Where(name => !string.IsNullOrEmpty(name))
            .SelectMany(ResourceIdentifiers.Variants)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (candidates.Length == 0)
        {
            yield break;
        }

        var resources = await resourceStore.FindRtApiResourcesByNameAsync(candidates);

        foreach (var resource in resources)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // FindRtApiResourcesByNameAsync is a plain name query and returns disabled entities
            // too — a disabled API resource must not be requestable.
            if (resource.Enabled)
            {
                yield return resource;
            }
        }
    }

    public ValueTask<string?> GetNameAsync(RtApiResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new ValueTask<string?>(resource.Name);
    }
}
