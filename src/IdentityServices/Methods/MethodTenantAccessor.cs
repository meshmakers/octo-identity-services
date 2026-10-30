using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Tenant of the CK method invocation that runs in this DI scope (AB#5672). A method handler runs on the bus
///     outside any HTTP request, but every identity store (user, token, authorization) resolves its tenant through
///     <see cref="IMultiTenancyResolverService" />, which reads the HTTP request. The handler binds the tenant of the
///     request here before it resolves a store; <see cref="MethodTenantResolverService" /> then answers with it.
/// </summary>
internal interface IMethodTenantAccessor
{
    /// <summary>The bound tenant repository, or <c>null</c> when no method tenant is bound in this scope.</summary>
    ITenantRepository? TenantRepository { get; }

    /// <summary>
    ///     Binds the tenant of the invocation. Returns <c>false</c> when the tenant does not exist; nothing is bound then.
    /// </summary>
    Task<bool> BindAsync(string tenantId);
}

internal sealed class MethodTenantAccessor(ISystemContext systemContext) : IMethodTenantAccessor
{
    public ITenantRepository? TenantRepository { get; private set; }

    public async Task<bool> BindAsync(string tenantId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        var repository = await systemContext.TryFindTenantRepositoryAsync(tenantId).ConfigureAwait(false);
        if (repository == null)
        {
            return false;
        }

        TenantRepository = repository;
        return true;
    }
}

/// <summary>
///     <see cref="IMultiTenancyResolverService" /> that prefers the tenant bound by a CK method invocation and falls back to
///     the HTTP request resolution of the infrastructure. In an HTTP request nothing is bound, so the behavior is unchanged.
/// </summary>
internal sealed class MethodTenantResolverService(
    IMethodTenantAccessor accessor,
    MultiTenancyResolverService httpResolver) : IMultiTenancyResolverService
{
    public ITenantRepository GetTenantRepository() => accessor.TenantRepository ?? httpResolver.GetTenantRepository();

    public string GetTenantId() => accessor.TenantRepository?.TenantId ?? httpResolver.GetTenantId();
}
