using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Caching.Memory;
using NSubstitute;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#6393: the cached tenant registry that turns a tenant id into a lightweight repository without the
///     existence probe / admin session / CK auto-import of <c>FindTenantRepositoryAsync</c>, and fails closed
///     for tenants it does not know.
/// </summary>
public class TenantRegistryTests
{
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());
    private readonly ManualTimeProvider _time = new();
    private readonly List<OctoTenant> _registered = [new("meshtest", "db-meshtest")];
    private readonly TenantRegistry _sut;

    public TenantRegistryTests()
    {
        _systemContext.TenantId.Returns("octosystem");
        _systemContext.DatabaseName.Returns("db-octosystem");
        var result = Substitute.For<IResultSet<OctoTenant>>();
        result.Items.Returns(_ => _registered.ToArray());
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(result);
        _systemContext.GetRegisteredTenantRepository(Arg.Any<OctoTenant>())
            .Returns(_ => Substitute.For<ITenantRepository>());
        _sut = new TenantRegistry(_systemContext, _cache, _time);
    }

    [Fact]
    public async Task TryGetRepositoryAsync_RegisteredTenant_UsesTheRegistryEntry()
    {
        var repository = await _sut.TryGetRepositoryAsync("meshtest");

        repository.Should().NotBeNull();
        _systemContext.Received(1).GetRegisteredTenantRepository(
            Arg.Is<OctoTenant>(t => t.TenantId == "meshtest" && t.DatabaseName == "db-meshtest"));
        await _systemContext.DidNotReceiveWithAnyArgs().FindTenantRepositoryAsync(default!);
        await _systemContext.DidNotReceiveWithAnyArgs().TryFindTenantRepositoryAsync(default!);
    }

    [Fact]
    public async Task TryGetRepositoryAsync_TenantIdIsCaseInsensitive()
    {
        (await _sut.TryGetRepositoryAsync("MeshTest")).Should().NotBeNull();
    }

    [Fact]
    public async Task TryGetRepositoryAsync_SystemTenant_NeedsNoRegistryRead()
    {
        var repository = await _sut.TryGetRepositoryAsync("octosystem");

        repository.Should().NotBeNull();
        _systemContext.Received(1).GetRegisteredTenantRepository(
            Arg.Is<OctoTenant>(t => t.TenantId == "octosystem" && t.DatabaseName == "db-octosystem"));
        await _systemContext.DidNotReceiveWithAnyArgs().GetAdminSessionAsync();
    }

    [Theory]
    [InlineData("ghost")]
    [InlineData("")]
    public async Task TryGetRepositoryAsync_UnknownTenant_ReturnsNullAndOpensNothing(string tenantId)
    {
        (await _sut.TryGetRepositoryAsync(tenantId)).Should().BeNull();

        _systemContext.DidNotReceiveWithAnyArgs().GetRegisteredTenantRepository(default!);
    }

    [Fact]
    public async Task TryGetRepositoryAsync_RepeatedLookups_ReadTheRegistryOnce()
    {
        await _sut.TryGetRepositoryAsync("meshtest");
        await _sut.TryGetRepositoryAsync("meshtest");
        await _sut.GetRegisteredTenantsAsync();

        await _systemContext.Received(1).GetAdminSessionAsync();
    }

    [Fact]
    public async Task TryGetRepositoryAsync_MissWithinRefreshInterval_DoesNotReReadTheRegistry()
    {
        await _sut.GetRegisteredTenantsAsync();
        _time.Advance(TimeSpan.FromSeconds(1));

        for (var i = 0; i < 5; i++)
        {
            (await _sut.TryGetRepositoryAsync("ghost-" + i)).Should().BeNull();
        }

        // Unknown tenant ids must not be an amplifier for registry reads.
        await _systemContext.Received(1).GetAdminSessionAsync();
    }

    [Fact]
    public async Task TryGetRepositoryAsync_MissAfterRefreshInterval_FindsAFreshlyCreatedTenant()
    {
        await _sut.GetRegisteredTenantsAsync();
        _registered.Add(new OctoTenant("fresh", "db-fresh"));
        _time.Advance(TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(1));

        (await _sut.TryGetRepositoryAsync("fresh")).Should().NotBeNull();
        await _systemContext.Received(2).GetAdminSessionAsync();
    }

    [Fact]
    public async Task TryGetRepositoryAsync_RegistryFailure_Throws_SoCallersFailClosed()
    {
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns<IResultSet<OctoTenant>>(_ => throw new InvalidOperationException("db down"));

        var act = () => _sut.TryGetRepositoryAsync("meshtest");

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
