using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     OpenIddict scope store projecting the existing per-tenant <see cref="RtApiScope" />
///     entities (AB#4991). Scope→audience resolution (<see cref="GetResourcesAsync" />) walks the
///     <see cref="RtApiResource" /> entities so issued access tokens carry the same <c>aud</c>
///     values as before the migration (golden-baseline pinned).
/// </summary>
/// <remarks>
///     The scope identifier exposed to OpenIddict is the scope NAME (unique per tenant).
///     Write operations are unsupported — scope CRUD goes through <see cref="IOctoResourceStore" />
///     (TenantApi controllers, default-configuration seeding).
/// </remarks>
public class OpenIddictScopeStore(IOctoResourceStore resourceStore) : IOpenIddictScopeStore<RtApiScope>
{
    private const string WritesUnsupportedMessage =
        "Scope write operations go through IOctoResourceStore, not OpenIddict.";

    public ValueTask<long> CountAsync(CancellationToken cancellationToken)
        => throw new NotSupportedException("Counting scopes through OpenIddict is not supported.");

    public ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RtApiScope>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the scope store are not supported.");

    public ValueTask CreateAsync(RtApiScope scope, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask DeleteAsync(RtApiScope scope, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    // The scope identifier IS the scope name (see class remarks).
    public ValueTask<RtApiScope?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => FindByNameAsync(identifier, cancellationToken);

    public async ValueTask<RtApiScope?> FindByNameAsync(string name, CancellationToken cancellationToken)
    {
        var scope = await resourceStore.GetApiScopeByNameAsync(name);
        if (scope is { Enabled: true })
        {
            return scope;
        }

        // OIDC identity resources (openid, profile, email, role, allowed_tenants, …) are stored
        // as RtIdentityResource but are requestable scopes on the wire — clients request them in
        // the scope parameter. Project them into the scope entity so OpenIddict's scope
        // validation accepts them.
        var identityResource = await resourceStore.GetIdentityResourceByNameAsync(name);
        if (identityResource is { Enabled: true })
        {
            return new RtApiScope
            {
                RtId = identityResource.RtId,
                Name = identityResource.Name,
                DisplayName = identityResource.DisplayName,
                Description = identityResource.Description,
                Enabled = identityResource.Enabled,
                ShowInDiscoveryDocument = identityResource.ShowInDiscoveryDocument,
                Claims = identityResource.Claims,
                IsEmphasized = identityResource.IsEmphasized,
                IsRequired = identityResource.IsRequired
            };
        }

        return null;
    }

    public async IAsyncEnumerable<RtApiScope> FindByNamesAsync(
        ImmutableArray<string> names,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var name in names)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var scope = await FindByNameAsync(name, cancellationToken);
            if (scope != null)
            {
                yield return scope;
            }
        }
    }

    public async IAsyncEnumerable<RtApiScope> FindByResourceAsync(
        string resource,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var apiResources = await resourceStore.FindRtApiResourcesByNameAsync([resource]);
        foreach (var apiResource in apiResources)
        {
            foreach (var scopeName in apiResource.Scopes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var scope = await FindByNameAsync(scopeName, cancellationToken);
                if (scope != null)
                {
                    yield return scope;
                }
            }
        }
    }

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RtApiScope>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the scope store are not supported.");

    public ValueTask<string?> GetDescriptionAsync(RtApiScope scope, CancellationToken cancellationToken)
        => new(scope.Description);

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(
        RtApiScope scope, CancellationToken cancellationToken)
        => new(ImmutableDictionary<CultureInfo, string>.Empty);

    public ValueTask<string?> GetDisplayNameAsync(RtApiScope scope, CancellationToken cancellationToken)
        => new(scope.DisplayName);

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(
        RtApiScope scope, CancellationToken cancellationToken)
        => new(ImmutableDictionary<CultureInfo, string>.Empty);

    public ValueTask<string?> GetIdAsync(RtApiScope scope, CancellationToken cancellationToken)
        => new(scope.Name);

    public ValueTask<string?> GetNameAsync(RtApiScope scope, CancellationToken cancellationToken)
        => new(scope.Name);

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RtApiScope scope, CancellationToken cancellationToken)
        => new(ImmutableDictionary<string, JsonElement>.Empty);

    public async ValueTask<ImmutableArray<string>> GetResourcesAsync(
        RtApiScope scope, CancellationToken cancellationToken)
    {
        // Audience resolution: all enabled API resources carrying this scope become aud values
        // (pre-migration wire format, pinned by the golden baseline tests).
        var apiResources = await resourceStore.FindRtApiResourcesByScopeNameAsync([scope.Name]);
        return apiResources
            .Where(r => r.Enabled)
            .Select(r => r.Name)
            .Distinct(StringComparer.Ordinal)
            .ToImmutableArray();
    }

    public ValueTask<RtApiScope> InstantiateAsync(CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public IAsyncEnumerable<RtApiScope> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => throw new NotSupportedException("Listing scopes through OpenIddict is not supported.");

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RtApiScope>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the scope store are not supported.");

    public ValueTask SetDescriptionAsync(RtApiScope scope, string? description, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetDescriptionsAsync(RtApiScope scope,
        ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetDisplayNameAsync(RtApiScope scope, string? name, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetDisplayNamesAsync(RtApiScope scope,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetNameAsync(RtApiScope scope, string? name, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetPropertiesAsync(RtApiScope scope,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask SetResourcesAsync(RtApiScope scope, ImmutableArray<string> resources,
        CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);

    public ValueTask UpdateAsync(RtApiScope scope, CancellationToken cancellationToken)
        => throw new NotSupportedException(WritesUnsupportedMessage);
}
