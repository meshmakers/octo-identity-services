using System.Diagnostics;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#8177: with the MongoDB user of tenant X missing, the token path of a user of tenant Y (which probes every
///     tenant database for cross-tenant mappings) must stay fast and, after the first failure, must not touch X at all.
///     The hung session below stands in for the ~10 s the driver spends on the failed SCRAM authentication.
/// </summary>
public class AllowedTenantsResolverBrokenTenantTests
{
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly IMemoryCache _cache = new MemoryCache(new MemoryCacheOptions());
    private readonly RtUser _user = new RtUserBuilder().WithUserName("alice").Build();
    private readonly AllowedTenantsResolver _sut;
    private int _brokenSessions;

    public AllowedTenantsResolverBrokenTenantTests()
    {
        var chain = Substitute.For<ICrossTenantShadowUserChainResolver>();
        chain.GetSourceChainAsync(Arg.Any<string?>()).Returns(Array.Empty<(string TenantId, string UserName)>());

        var registry = Substitute.For<IResultSet<OctoTenant>>();
        registry.Items.Returns(new[] { "accounting", "mapped", "meshmaker" }
            .Select(t => new OctoTenant(t, "db-" + t)).ToArray());
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(registry);

        SetupHealthy("accounting", hasMapping: false);
        SetupHealthy("mapped", hasMapping: true);

        var broken = Substitute.For<ITenantRepository>();
        broken.GetSessionAsync().Returns(_ =>
        {
            Interlocked.Increment(ref _brokenSessions);
            return new TaskCompletionSource<IOctoSession>().Task; // never answers, like a failing SCRAM handshake
        });
        _systemContext.GetRegisteredTenantRepository(
            Arg.Is<OctoTenant>(t => t.TenantId == "meshmaker")).Returns(broken);

        var guard = new TenantProbeGuard(
            Options.Create(new TenantProbeGuardOptions { ProbeTimeout = TimeSpan.FromMilliseconds(250) }),
            Options.Create(new OctoSystemConfiguration { DatabaseUser = "octo-system-ds-user-{0}" }),
            NullLogger<TenantProbeGuard>.Instance);
        _sut = new AllowedTenantsResolver(_systemContext, new TenantRegistry(_systemContext, _cache), chain, _cache,
            guard, NullLogger<AllowedTenantsResolver>.Instance);
    }

    [Fact]
    public async Task TheFirstTokenRequest_IsBoundedByTheProbeTimeout_AndStillResolvesTheHealthyTenants()
    {
        var watch = Stopwatch.StartNew();
        var result = await _sut.ResolveAsync("login", _user);
        watch.Stop();

        result.Should().BeEquivalentTo("login", "mapped");
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task EveryFurtherTokenRequest_StaysFast_AndDoesNotTouchTheBrokenTenant()
    {
        await _sut.ResolveAsync("login", _user); // opens the circuit of the broken tenant
        _brokenSessions.Should().Be(1, "the second BFS tier already finds the circuit open");
        var before = _brokenSessions;

        var watch = Stopwatch.StartNew();
        for (var i = 0; i < 10; i++)
        {
            // another user per request, so the mapping cache cannot hide the probe
            var result = await _sut.ResolveAsync("login",
                new RtUserBuilder().WithUserName("user" + i).Build());
            result.Should().BeEquivalentTo("login", "mapped");
        }

        watch.Stop();
        _brokenSessions.Should().Be(before, "the open circuit never reaches the broken tenant's database");
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(1));
    }

    private void SetupHealthy(string tenantId, bool hasMapping)
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
        _systemContext.GetRegisteredTenantRepository(Arg.Is<OctoTenant>(t => t.TenantId == tenantId))
            .Returns(repository);
    }
}
