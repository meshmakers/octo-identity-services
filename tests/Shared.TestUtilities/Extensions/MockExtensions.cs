using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NSubstitute;
using Shared.TestUtilities.Fakes;

namespace Shared.TestUtilities.Extensions;

public static class MockExtensions
{
    public static (ITenantRepository Repository, FakeOctoSession Session) SetupTenantRepository(
        this IMultiTenancyResolverService multiTenancyResolver,
        string tenantId = "TestTenant")
    {
        var tenantRepository = Substitute.For<ITenantRepository>();
        var session = new FakeOctoSession();

        tenantRepository.TenantId.Returns(tenantId);
        tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(session));

        multiTenancyResolver.GetTenantRepository().Returns(tenantRepository);

        return (tenantRepository, session);
    }
}
