using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5487: the Identity CORS policy cache must not freeze an empty origin list and must heal on its own
///     (TTL), so a tenant whose app client is mirrored in after the first request is not blind to the SPA.
/// </summary>
public class IdentityCorsPolicyProviderTests
{
    private const string SystemTenantId = "octosystem";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantRepository _systemRepo = Substitute.For<ITenantRepository>();
    private readonly ManualTimeProvider _time = new();
    private RtClient[] _clients = Array.Empty<RtClient>();
    private int _loadCount;

    public IdentityCorsPolicyProviderTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);
        _systemContext.IsSystemTenantExistingAsync().Returns(true);
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());

        var registry = Substitute.For<IResultSet<OctoTenant>>();
        registry.Items.Returns(Array.Empty<OctoTenant>());
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(registry);

        _systemContext.TryFindTenantRepositoryAsync(SystemTenantId).Returns(_systemRepo);
        _systemRepo.GetSessionAsync().Returns(Substitute.For<IOctoSession>());
        _systemRepo.GetRtEntitiesByTypeAsync<RtClient>(Arg.Any<IOctoSession>(), Arg.Any<RtEntityQueryOptions>())
            .Returns(_ =>
            {
                _loadCount++;
                var result = Substitute.For<IResultSet<RtClient>>();
                result.Items.Returns(_clients);
                return result;
            });
    }

    private IdentityCorsPolicyProvider CreateSut(int cacheSeconds = 60)
    {
        var services = new ServiceCollection().AddSingleton(_systemContext).BuildServiceProvider();
        return new IdentityCorsPolicyProvider(
            services,
            NullLogger<IdentityCorsPolicyProvider>.Instance,
            Options.Create(new OctoIdentityServicesOptions { CorsPolicyCacheSeconds = cacheSeconds }),
            _time);
    }

    private void SetOrigins(params string[] origins) =>
        _clients = origins.Length == 0
            ? Array.Empty<RtClient>()
            : new[] { new RtClientBuilder().WithClientId("studio").WithCorsOrigins(origins).Build() };

    [Fact]
    public void DefaultCacheLifetime_IsSixtySeconds()
    {
        new OctoIdentityServicesOptions().CorsPolicyCacheSeconds.Should().Be(60);
    }

    [Fact]
    public async Task EmptyPolicy_IsNotCached_AndRecoversOnceOriginsExist()
    {
        var sut = CreateSut();

        var first = await sut.GetPolicyAsync(null!, null);
        first!.Origins.Should().BeEmpty();
        var second = await sut.GetPolicyAsync(null!, null);
        second!.Origins.Should().BeEmpty();
        _loadCount.Should().Be(2, "an empty policy must be rebuilt on every request, not cached");

        // The app client is mirrored in afterwards: the very next request sees it, with no event and no TTL wait.
        SetOrigins("https://app.example");
        var healed = await sut.GetPolicyAsync(null!, null);
        healed!.Origins.Should().Equal("https://app.example");

        // From now on the policy is cached.
        var cached = await sut.GetPolicyAsync(null!, null);
        cached.Should().BeSameAs(healed);
        _loadCount.Should().Be(3);
    }

    [Fact]
    public async Task NonEmptyPolicy_IsCachedUntilTtlExpires_ThenReloaded()
    {
        SetOrigins("https://old.example");
        var sut = CreateSut();

        var first = await sut.GetPolicyAsync(null!, null);
        _time.Advance(TimeSpan.FromSeconds(59));
        var stillCached = await sut.GetPolicyAsync(null!, null);
        stillCached.Should().BeSameAs(first);
        _loadCount.Should().Be(1);

        // The origin was removed on another pod without an event reaching this one.
        SetOrigins("https://new.example");
        _time.Advance(TimeSpan.FromSeconds(2));
        var reloaded = await sut.GetPolicyAsync(null!, null);

        reloaded.Should().NotBeSameAs(first);
        reloaded!.Origins.Should().Equal("https://new.example");
        _loadCount.Should().Be(2);
    }

    [Fact]
    public async Task TtlOfZero_DisablesTimeBasedExpiry()
    {
        SetOrigins("https://app.example");
        var sut = CreateSut(cacheSeconds: 0);

        var first = await sut.GetPolicyAsync(null!, null);
        _time.Advance(TimeSpan.FromDays(30));
        var second = await sut.GetPolicyAsync(null!, null);

        second.Should().BeSameAs(first);
        _loadCount.Should().Be(1);
    }

    [Fact]
    public async Task InvalidateCache_ForcesReload()
    {
        SetOrigins("https://app.example");
        var sut = CreateSut();
        await sut.GetPolicyAsync(null!, null);

        SetOrigins("https://app.example", "https://second.example");
        sut.InvalidateCache();
        var reloaded = await sut.GetPolicyAsync(null!, null);

        reloaded!.Origins.Should().BeEquivalentTo("https://app.example", "https://second.example");
        _loadCount.Should().Be(2);
    }

    [Fact]
    public async Task IsOriginAllowed_FollowsTheSameCache()
    {
        var sut = CreateSut();

        (await sut.IsOriginAllowedAsync("https://app.example")).Should().BeFalse();
        SetOrigins("https://app.example");
        (await sut.IsOriginAllowedAsync("https://app.example")).Should().BeTrue();
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
