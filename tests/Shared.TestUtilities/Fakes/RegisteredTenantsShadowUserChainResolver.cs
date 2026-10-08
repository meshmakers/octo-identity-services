using IdentityServerPersistence.Services;

namespace Shared.TestUtilities.Fakes;

/// <summary>
///     <see cref="ICrossTenantShadowUserChainResolver" /> over a fixed tenant registry, so unit tests
///     exercise the real registry-aware unwinding (<see cref="CrossTenantShadowUserName.GetSourceChainAsync" />)
///     without a system database. Tenant ids added later through <see cref="Register" /> count too.
/// </summary>
public sealed class RegisteredTenantsShadowUserChainResolver(params string[] registeredTenantIds)
    : ICrossTenantShadowUserChainResolver
{
    private readonly HashSet<string> _registered = new(registeredTenantIds, StringComparer.OrdinalIgnoreCase);

    /// <summary>Adds tenant ids to the registry.</summary>
    public void Register(params string[] tenantIds) => _registered.UnionWith(tenantIds);

    public Task<IReadOnlyList<(string TenantId, string UserName)>> GetSourceChainAsync(string? userName)
        => CrossTenantShadowUserName.GetSourceChainAsync(userName, IsRegisteredAsync);

    public Task<(string TenantId, string UserName)> GetRootIdentityAsync(string tenantId, string userName)
        => CrossTenantShadowUserName.GetRootIdentityAsync(tenantId, userName, IsRegisteredAsync);

    private Task<bool> IsRegisteredAsync(string tenantId) => Task.FromResult(_registered.Contains(tenantId));
}
