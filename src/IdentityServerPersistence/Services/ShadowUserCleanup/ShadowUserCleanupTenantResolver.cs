using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;

namespace IdentityServerPersistence.Services.ShadowUserCleanup;

/// <summary>Binds a store to one tenant repository, independent of any request's tenant (AB#8305).</summary>
internal sealed class ShadowUserCleanupTenantResolver(ITenantRepository repository) : IMultiTenancyResolverService
{
    public ITenantRepository GetTenantRepository() => repository;
    public string GetTenantId() => repository.TenantId;
}
