using IdentityServerPersistence.SystemStores;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services;

/// <summary>
///     The OctoTenant identity providers ("Login via &lt;parent&gt;") the login page of the current tenant offers (AB#8367).
/// </summary>
public interface IOctoTenantLoginProviders
{
    /// <summary>
    ///     The enabled OctoTenant identity providers of the tenant the identity-provider store is bound to whose parent
    ///     the cross-tenant ancestry check (<see cref="ICrossTenantAncestryGuard" />, AB#8339) lets through. Under
    ///     <see cref="CrossTenantAncestryMode.Enforce" /> a provider that names a tenant outside the registry ancestor
    ///     chain is left out — the tenant switch it starts is always refused. Under
    ///     <see cref="CrossTenantAncestryMode.Warn" /> it stays, and the guard logs its "would be denied" warning.
    /// </summary>
    Task<IReadOnlyList<RtOctoTenantIdentityProvider>> GetOfferedAsync();
}

/// <inheritdoc />
public sealed class OctoTenantLoginProviders(
    IOctoIdentityProviderStore identityProviderStore,
    ICrossTenantAncestryGuard ancestryGuard) : IOctoTenantLoginProviders
{
    /// <summary>The operation name in the guard's log lines.</summary>
    public const string Operation = "login page provider list";

    /// <inheritdoc />
    public async Task<IReadOnlyList<RtOctoTenantIdentityProvider>> GetOfferedAsync()
    {
        var candidates = (await identityProviderStore.GetAllAsync())
            .OfType<RtOctoTenantIdentityProvider>()
            .Where(p => p.IsEnabled && !string.IsNullOrEmpty(p.ParentTenantId))
            .ToList();
        if (candidates.Count == 0)
        {
            return candidates;
        }

        // One registry read for all providers of the page.
        var tenantId = identityProviderStore.TenantId;
        var registryAncestors = await ancestryGuard.GetRegistryAncestorsAsync(tenantId);
        return candidates
            .Where(p => ancestryGuard.IsTrustedAncestor(tenantId, registryAncestors, p.ParentTenantId!, Operation))
            .ToList();
    }
}
