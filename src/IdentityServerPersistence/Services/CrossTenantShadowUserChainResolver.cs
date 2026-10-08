using Meshmakers.Octo.Runtime.Contracts.MongoDb;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Unwinds cross-tenant shadow user names (<c>xt_{tenant}_{user}</c>) against the tenant registry, so
///     a tenant id containing an underscore cannot be misread as a shorter tenant id plus a nested
///     <c>xt_</c> chain (AB#5708). See <see cref="CrossTenantShadowUserName.GetSourceChainAsync" />.
/// </summary>
public interface ICrossTenantShadowUserChainResolver
{
    /// <summary>The source identities of <paramref name="userName" />, nearest first; empty for a local user.</summary>
    Task<IReadOnlyList<(string TenantId, string UserName)>> GetSourceChainAsync(string? userName);

    /// <summary>The home identity <paramref name="userName" /> in <paramref name="tenantId" /> unwinds to.</summary>
    Task<(string TenantId, string UserName)> GetRootIdentityAsync(string tenantId, string userName);
}

/// <summary>
///     Registry-backed <see cref="ICrossTenantShadowUserChainResolver" />. Registry probes are cached for
///     the lifetime of the (scoped) instance — one token issuance or request.
/// </summary>
public sealed class CrossTenantShadowUserChainResolver(ISystemContext systemContext)
    : ICrossTenantShadowUserChainResolver
{
    private readonly Dictionary<string, bool> _registered = new(StringComparer.OrdinalIgnoreCase);

    public Task<IReadOnlyList<(string TenantId, string UserName)>> GetSourceChainAsync(string? userName)
        => CrossTenantShadowUserName.GetSourceChainAsync(userName, IsTenantRegisteredAsync);

    public Task<(string TenantId, string UserName)> GetRootIdentityAsync(string tenantId, string userName)
        => CrossTenantShadowUserName.GetRootIdentityAsync(tenantId, userName, IsTenantRegisteredAsync);

    private async Task<bool> IsTenantRegisteredAsync(string tenantId)
    {
        if (!_registered.TryGetValue(tenantId, out var registered))
        {
            registered = await systemContext.IsTenantRegisteredAsync(tenantId);
            _registered[tenantId] = registered;
        }

        return registered;
    }
}
