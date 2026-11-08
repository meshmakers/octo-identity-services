using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Binds a request-scoped store (user, group, mapping store) to one tenant repository, independent of the request's
///     tenant — for the cross-tenant services that read a tenant other than the one the request was routed to.
/// </summary>
internal sealed class FixedTenantRepositoryResolver(ITenantRepository repository) : IMultiTenancyResolverService
{
    public ITenantRepository GetTenantRepository() => repository;

    public string GetTenantId() => repository.TenantId;
}
