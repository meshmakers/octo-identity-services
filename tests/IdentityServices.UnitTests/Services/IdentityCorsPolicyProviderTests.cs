using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Shared.TestUtilities.Fakes;
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
    private TaskCompletionSource? _gate;
    private Exception? _failNext;
    private TaskCompletionSource? _failGate;

    public IdentityCorsPolicyProviderTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);
        _systemContext.IsSystemTenantExistingAsync().Returns(async _ =>
        {
            var failure = Interlocked.Exchange(ref _failNext, null);
            if (failure == null)
            {
                return true;
            }

            // A failing load can be held like a successful one, so waiters can join it.
            var gate = _failGate;
            if (gate != null)
            {
                await gate.Task;
            }

            throw failure;
        });
        _systemContext.GetAdminSessionAsync().Returns(Substitute.For<IOctoAdminSession>());

        var registry = Substitute.For<IResultSet<OctoTenant>>();
        registry.Items.Returns(Array.Empty<OctoTenant>());
        _systemContext.GetAllTenantsAsync(Arg.Any<IOctoAdminSession>(), Arg.Any<int?>(), Arg.Any<int?>())
            .Returns(registry);

        _systemContext.TryFindTenantRepositoryAsync(SystemTenantId).Returns(_systemRepo);
        _systemRepo.GetSessionAsync().Returns(Substitute.For<IOctoSession>());
        _systemRepo.GetRtEntitiesByTypeAsync<RtClient>(Arg.Any<IOctoSession>(), Arg.Any<RtEntityQueryOptions>())
            .Returns(async _ =>
            {
                Interlocked.Increment(ref _loadCount);
                // The clients are read when the load starts; the gate holds the load "in the database".
                var clients = _clients;
                var gate = _gate;
                if (gate != null)
                {
                    await gate.Task;
                }

                var result = Substitute.For<IResultSet<RtClient>>();
                result.Items.Returns(clients);
                return result;
            });
    }

    private IdentityCorsPolicyProvider CreateSut(int cacheSeconds = 60, ILogger<IdentityCorsPolicyProvider>? logger = null)
    {
        var services = new ServiceCollection().AddSingleton(_systemContext).BuildServiceProvider();
        return new IdentityCorsPolicyProvider(
            services,
            logger ?? NullLogger<IdentityCorsPolicyProvider>.Instance,
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

    // ---------- AB#8035: single-flight rebuild and log levels ----------

    private async Task WaitForLoadsAsync(int expected)
    {
        for (var i = 0; i < 500 && Volatile.Read(ref _loadCount) < expected; i++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        Volatile.Read(ref _loadCount).Should().Be(expected);
    }

    [Fact]
    public async Task ParallelRequestsAtExpiry_ShareOneLoad_AndGetTheSamePolicy()
    {
        SetOrigins("https://app.example");
        var sut = CreateSut();
        await sut.GetPolicyAsync(null!, null);
        _time.Advance(TimeSpan.FromSeconds(61));

        _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var requests = Enumerable.Range(0, 32)
            .Select(_ => Task.Run(() => sut.GetPolicyAsync(null!, null), TestContext.Current.CancellationToken))
            .ToArray();
        await WaitForLoadsAsync(2);
        await Task.Delay(50, TestContext.Current.CancellationToken);
        _loadCount.Should().Be(2, "the requests that see the expired entry wait for one load");

        _gate.SetResult();
        var policies = await Task.WhenAll(requests);

        policies.Distinct().Should().ContainSingle("all requests get the policy of the one load");
        _loadCount.Should().Be(2);
        (await sut.GetPolicyAsync(null!, null)).Should().BeSameAs(policies[0], "the shared load was cached");
    }

    [Fact]
    public async Task InvalidationDuringALoad_StartsANewLoad_AndTheStaleResultIsNotCached()
    {
        SetOrigins("https://old.example");
        var sut = CreateSut();
        _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var gate = _gate;
        var stale = sut.GetPolicyAsync(null!, null);
        await WaitForLoadsAsync(1);

        _gate = null;
        SetOrigins("https://new.example");
        sut.InvalidateCache();
        var fresh = await sut.GetPolicyAsync(null!, null);
        fresh!.Origins.Should().Equal(["https://new.example"], "a request after the invalidation does not join the old load");

        gate.SetResult();
        (await stale)!.Origins.Should().Equal("https://old.example");

        (await sut.GetPolicyAsync(null!, null)).Should().BeSameAs(fresh, "the load started before the invalidation never publishes");
        _loadCount.Should().Be(2);
    }

    [Fact]
    public async Task EmptyOrigins_ConcurrentRequestsShareOneLoad_AndTheResultIsStillNotCached()
    {
        var sut = CreateSut();
        _gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var requests = Enumerable.Range(0, 16)
            .Select(_ => Task.Run(() => sut.GetPolicyAsync(null!, null), TestContext.Current.CancellationToken))
            .ToArray();
        await WaitForLoadsAsync(1);
        await Task.Delay(50, TestContext.Current.CancellationToken);
        _loadCount.Should().Be(1, "no stampede while the origin list is empty");

        _gate.SetResult();
        (await Task.WhenAll(requests)).Should().OnlyContain(p => p!.Origins.Count == 0);

        _gate = null;
        await sut.GetPolicyAsync(null!, null);
        _loadCount.Should().Be(2, "an empty policy is still not cached (AB#5487)");
    }

    [Fact]
    public async Task FailedLoad_IsHandedToItsWaiters_AndTheNextRequestRetries()
    {
        SetOrigins("https://app.example");
        var sut = CreateSut();
        _failNext = new InvalidOperationException("registry unavailable");

        var failing = async () => await sut.GetPolicyAsync(null!, null);
        await failing.Should().ThrowAsync<InvalidOperationException>();

        var retried = await sut.GetPolicyAsync(null!, null);
        retried!.Origins.Should().Equal("https://app.example");
        (await sut.GetPolicyAsync(null!, null)).Should().BeSameAs(retried);
    }

    [Fact]
    public async Task FailedLoad_WithConcurrentWaiters_FailsThemAll_WithoutPoisoningTheCache()
    {
        SetOrigins("https://app.example");
        var sut = CreateSut();
        await sut.GetPolicyAsync(null!, null);
        _time.Advance(TimeSpan.FromSeconds(61));
        _failNext = new InvalidOperationException("registry unavailable");
        _failGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var requests = Enumerable.Range(0, 8).Select(_ => sut.GetPolicyAsync(null!, null)).ToArray();
        requests.Should().OnlyContain(r => !r.IsCompleted, "all requests wait for the one failing load");
        _failGate.SetResult();
        foreach (var request in requests)
        {
            var wait = async () => await request;
            await wait.Should().ThrowAsync<InvalidOperationException>();
        }

        (await sut.GetPolicyAsync(null!, null))!.Origins.Should().Equal("https://app.example");
    }

    [Fact]
    public async Task Rebuild_LogsAtDebug_AndInformationOnlyWhenTheOriginsChange()
    {
        var logger = new CapturingLogger<IdentityCorsPolicyProvider>();
        SetOrigins("https://app.example");
        var sut = CreateSut(logger: logger);

        await sut.GetPolicyAsync(null!, null);
        logger.Messages.Should().ContainSingle(m => m.StartsWith("[Information] Identity CORS origins changed: 1 origins"));

        _time.Advance(TimeSpan.FromSeconds(61));
        await sut.GetPolicyAsync(null!, null);
        logger.Messages.Count(m => m.StartsWith("[Debug] Creating CORS policy")).Should().Be(2);
        logger.Messages.Count(m => m.StartsWith("[Information]")).Should().Be(1, "a TTL rebuild without a change logs no Information");

        SetOrigins("https://app.example", "https://second.example");
        _time.Advance(TimeSpan.FromSeconds(61));
        await sut.GetPolicyAsync(null!, null);
        logger.Messages.Should().Contain(m =>
            m.StartsWith("[Information] Identity CORS origins changed: 2 origins")
            && m.Contains("added: https://second.example;") && m.Contains("removed: )"));

        SetOrigins("https://second.example");
        sut.InvalidateCache();
        await sut.GetPolicyAsync(null!, null);
        logger.Messages.Should().Contain(m =>
            m.StartsWith("[Information] Identity CORS origins changed: 1 origins") && m.Contains("removed: https://app.example)"));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
