using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#6307: the token endpoint resolved a mapping check per tenant through uncached
///     <c>FindTenantRepositoryAsync</c> calls (7–9 MongoDB round trips each). The registry list and the
///     per-tenant mapping lookup are now cached for a short TTL; the resulting allowed tenants stay the same.
///     AB#6308: even on a cache miss the lookup takes the database name from the registry entry and builds the
///     repository without an existence probe or CK auto-import (<c>GetRegisteredTenantRepository</c>).
/// </summary>
public class AllowedTenantsResolverCacheTests
{
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ICrossTenantShadowUserChainResolver _chain = Substitute.For<ICrossTenantShadowUserChainResolver>();
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());
    private readonly RtUser _user = new RtUserBuilder().WithUserName("alice").Build();
    private readonly AllowedTenantsResolver _sut;

    public AllowedTenantsResolverCacheTests()
    {
        _chain.GetSourceChainAsync(Arg.Any<string?>())
            .Returns(Array.Empty<(string TenantId, string UserName)>());

        var registry = Substitute.For<IResultSet<OctoTenant>>();
        registry.Items.Returns(new[] { "login", "mapped", "unmapped", "broken" }
            .Select(t => new OctoTenant(t, "db-" + t)).ToArray());
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(registry);

        SetupTenant("mapped", hasMapping: true);
        SetupTenant("unmapped", hasMapping: false);
        _systemContext.GetRegisteredTenantRepository(Registered("broken")).Returns<ITenantRepository>(_ => throw new InvalidOperationException("db down"));

        _systemContext.ClearReceivedCalls(); // setup calls are not part of the behaviour under test
        _sut = new AllowedTenantsResolver(_systemContext, _chain, _cache, NullLogger<AllowedTenantsResolver>.Instance);
    }

    [Fact]
    public async Task ResolveAsync_ReturnsLoginTenantAndMappedTenants_OnlyForMatchingMappings()
    {
        var result = await _sut.ResolveAsync("login", _user);

        result.Should().BeEquivalentTo("login", "mapped");
    }

    [Fact]
    public async Task ResolveAsync_DoesNotResolveTheLoginTenantItself()
    {
        await _sut.ResolveAsync("login", _user);

        _systemContext.DidNotReceive().GetRegisteredTenantRepository(Registered("login"));
    }

    [Fact]
    public async Task ResolveAsync_SecondCall_ReusesRegistryAndMappingLookups()
    {
        var first = await _sut.ResolveAsync("login", _user);
        _systemContext.ClearReceivedCalls();

        var second = await _sut.ResolveAsync("login", _user);

        second.Should().BeEquivalentTo(first);
        await _systemContext.DidNotReceiveWithAnyArgs().GetAdminSessionAsync();
        _systemContext.DidNotReceive().GetRegisteredTenantRepository(Registered("mapped"));
        _systemContext.DidNotReceive().GetRegisteredTenantRepository(Registered("unmapped"));
    }

    [Fact]
    public async Task ResolveAsync_NegativeResultsAreCachedToo()
    {
        // First resolution: "unmapped" is probed from the login tenant and, after "mapped" matched,
        // once more from the mapped tenant's shadow user (two distinct lookups).
        await _sut.ResolveAsync("login", _user);
        _systemContext.Received(2).GetRegisteredTenantRepository(Registered("unmapped"));

        await _sut.ResolveAsync("login", _user);

        _systemContext.Received(2).GetRegisteredTenantRepository(Registered("unmapped"));
    }

    [Fact]
    public async Task ResolveAsync_FailedLookupIsNotCachedAndDoesNotBreakResolution()
    {
        await _sut.ResolveAsync("login", _user);
        var result = await _sut.ResolveAsync("login", _user);

        result.Should().BeEquivalentTo("login", "mapped");
        // Two BFS probes per resolution, none of them served from the cache.
        _systemContext.Received(4).GetRegisteredTenantRepository(Registered("broken"));
    }

    [Fact]
    public async Task ResolveAsync_DifferentUsers_DoNotShareMappingResults()
    {
        await _sut.ResolveAsync("login", _user);
        await _sut.ResolveAsync("login", new RtUserBuilder().WithUserName("bob").Build());

        _systemContext.Received(2).GetRegisteredTenantRepository(Registered("mapped"));
    }

    private static OctoTenant Registered(string tenantId) =>
        Arg.Is<OctoTenant>(t => t.TenantId == tenantId && t.DatabaseName == "db-" + tenantId);

    [Fact]
    public async Task ResolveAsync_CacheMiss_NeverResolvesTenantsThroughTheHeavyPath()
    {
        await _sut.ResolveAsync("login", _user);

        // No existence probe and no CK auto-import per tenant: the cost of a miss is the single mapping query.
        await _systemContext.DidNotReceiveWithAnyArgs().FindTenantRepositoryAsync(default!);
        await _systemContext.DidNotReceiveWithAnyArgs().TryFindTenantRepositoryAsync(default!);
        await _systemContext.DidNotReceiveWithAnyArgs().TryFindTenantContextAsync(default!);
        await _systemContext.DidNotReceive().IsSystemTenantExistingAsync();
    }

    [Fact]
    public async Task ResolveAsync_CacheMiss_RegistryIsReadOnceNoMatterHowManyTenantsExist()
    {
        await _sut.ResolveAsync("login", _user);

        await _systemContext.Received(1).GetAllTenantsAsync(
            Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>());
        await _systemContext.Received(1).GetAdminSessionAsync();
    }

    private void SetupTenant(string tenantId, bool hasMapping)
    {
        var repository = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        repository.TenantId.Returns(tenantId);
        repository.GetSessionAsync().Returns(session);
        var mappings = Substitute.For<IResultSet<RtExternalTenantUserMapping>>();
        mappings.Items.Returns(hasMapping
            ? new[] { new RtExternalTenantUserMapping() }
            : Array.Empty<RtExternalTenantUserMapping>());
        repository.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(mappings);
        _systemContext.GetRegisteredTenantRepository(Registered(tenantId)).Returns(repository);
    }
}
