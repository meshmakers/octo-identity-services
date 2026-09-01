using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// Stubs <see cref="IMultiTenancyResolverService"/> to always resolve to a fixed tenant repository.
/// Used in integration tests that run outside an HTTP request context.
/// </summary>
internal sealed class FixedTenantResolver(ITenantRepository repository) : IMultiTenancyResolverService
{
    public ITenantRepository GetTenantRepository() => repository;
    public string GetTenantId() => repository.TenantId;
}
