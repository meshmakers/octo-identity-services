using System.Net;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using MongoDB.Driver.Core.Clusters;
using MongoDB.Driver.Core.Connections;
using MongoDB.Driver.Core.Servers;
using NSubstitute;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#8177: a tenant database that cannot be authenticated (its MongoDB user is missing) used to cost every probe
///     ~10 s. The guard bounds a probe, opens a per-tenant circuit after a failure and names tenant and user in the log.
/// </summary>
public class TenantProbeGuardTests
{
    private static readonly OctoTenant Broken = new("meshmaker", "meshmakers");
    private readonly CapturingLogger<TenantProbeGuard> _logger = new();
    private readonly ManualTimeProvider _time = new();

    private TenantProbeGuard CreateSut(TimeSpan? timeout = null, TimeSpan? open = null) =>
        new(Options.Create(new TenantProbeGuardOptions
            {
                ProbeTimeout = timeout ?? TimeSpan.FromMilliseconds(200),
                OpenDuration = open ?? TimeSpan.FromSeconds(60)
            }),
            Options.Create(new OctoSystemConfiguration { DatabaseUser = "octo-system-ds-user-{0}" }), _logger, _time);

    private static MongoAuthenticationException AuthFailure() =>
        new(new ConnectionId(new ServerId(new ClusterId(1), new DnsEndPoint("localhost", 27017))),
            "Unable to authenticate using sasl protocol mechanism SCRAM-SHA-1.");

    [Fact]
    public async Task ASuccessfulProbe_ReturnsItsValue()
    {
        var result = await CreateSut().RunAsync(Broken, "test", () => Task.FromResult(42));

        result.Should().Be(new TenantProbeResult<int>(true, 42));
    }

    [Fact]
    public async Task AProbeThatHangs_IsAbandonedAtTheTimeout()
    {
        var sut = CreateSut(timeout: TimeSpan.FromMilliseconds(100));
        var started = DateTime.UtcNow;

        var result = await sut.RunAsync<int>(Broken, "test", () => new TaskCompletionSource<int>().Task);

        result.Succeeded.Should().BeFalse();
        (DateTime.UtcNow - started).Should().BeLessThan(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task AfterAFailure_TheTenantIsNotTouchedAgain_UntilTheCircuitHasHalfOpened()
    {
        var sut = CreateSut(open: TimeSpan.FromSeconds(30));
        var calls = 0;
        Task<int> Failing()
        {
            Interlocked.Increment(ref calls);
            throw AuthFailure();
        }

        (await sut.RunAsync(Broken, "test", Failing)).Succeeded.Should().BeFalse();
        for (var i = 0; i < 5; i++)
        {
            (await sut.RunAsync(Broken, "test", Failing)).Succeeded.Should().BeFalse();
        }

        calls.Should().Be(1, "while the circuit is open the broken tenant's database is not contacted");

        _time.Advance(TimeSpan.FromSeconds(31));

        (await sut.RunAsync(Broken, "test", Failing)).Succeeded.Should().BeFalse();
        calls.Should().Be(2, "after the open duration exactly one request probes again");
    }

    [Fact]
    public async Task ARecoveredTenant_ClosesTheCircuit()
    {
        var sut = CreateSut(open: TimeSpan.FromSeconds(30));
        await sut.RunAsync<int>(Broken, "test", () => throw AuthFailure());
        _time.Advance(TimeSpan.FromSeconds(31));

        (await sut.RunAsync(Broken, "test", () => Task.FromResult(1))).Succeeded.Should().BeTrue();
        (await sut.RunAsync(Broken, "test", () => Task.FromResult(2))).Should().Be(new TenantProbeResult<int>(true, 2));
    }

    [Fact]
    public async Task ABrokenTenant_DoesNotAffectAnotherTenant()
    {
        var sut = CreateSut();
        await sut.RunAsync<int>(Broken, "test", () => throw AuthFailure());

        var healthy = await sut.RunAsync(new OctoTenant("accounting", "accounting"), "test", () => Task.FromResult(7));

        healthy.Should().Be(new TenantProbeResult<int>(true, 7));
    }

    [Fact]
    public async Task AnAuthenticationFailure_IsLoggedOnce_NamingTenantDatabaseAndUser()
    {
        var sut = CreateSut();

        await sut.RunAsync<int>(Broken, "external tenant user mapping lookup", () => throw AuthFailure());
        await sut.RunAsync<int>(Broken, "external tenant user mapping lookup", () => throw AuthFailure());

        var text = _logger.AllText;
        text.Should().Contain("meshmaker").And.Contain("'meshmakers'").And.Contain("octo-system-ds-user-meshmakers");
        _logger.Messages.Should().ContainSingle("the open circuit answers without logging again");
    }

    [Fact]
    public async Task ASlowSuccess_DoesNotClearTheCircuitAnotherProbeOpenedMeanwhile()
    {
        var sut = CreateSut(timeout: TimeSpan.FromSeconds(10), open: TimeSpan.FromSeconds(30));
        var slow = new TaskCompletionSource<int>();
        var slowProbe = sut.RunAsync(Broken, "test", () => slow.Task); // started while the circuit was closed

        await sut.RunAsync<int>(Broken, "test", () => throw AuthFailure()); // another probe opens the circuit
        slow.SetResult(1);
        (await slowProbe).Succeeded.Should().BeTrue();

        var calls = 0;
        (await sut.RunAsync(Broken, "test", () =>
        {
            calls++;
            return Task.FromResult(2);
        })).Succeeded.Should().BeFalse("the overlapping success must not have closed the circuit");
        calls.Should().Be(0);
    }

    private TenantProbeGuard CreateHealingSut(ISystemContext systemContext) =>
        new(Options.Create(new TenantProbeGuardOptions
            {
                ProbeTimeout = TimeSpan.FromMilliseconds(200), OpenDuration = TimeSpan.FromSeconds(60)
            }),
            Options.Create(new OctoSystemConfiguration { DatabaseUser = "octo-system-ds-user-{0}" }), _logger, _time,
            systemContext, new TenantDatabaseUserHealer(_time));

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task AnAuthenticationFailure_RecreatesTheMissingUser_AndTheCircuitClosesAtOnce()
    {
        // AB#8177: a user dropped under a RUNNING tenant heals without a restart, long before the circuit would half-open.
        var systemContext = Substitute.For<ISystemContext>();
        systemContext.EnsureTenantDatabaseUserAsync("meshmaker").Returns(TenantDatabaseUserEnsureResult.Created);
        var sut = CreateHealingSut(systemContext);

        (await sut.RunAsync<int>(Broken, "test", () => throw AuthFailure())).Succeeded.Should().BeFalse();
        await WaitUntilAsync(() => systemContext.ReceivedCalls().Any());

        await systemContext.Received(1).EnsureTenantDatabaseUserAsync("meshmaker");
        var healed = false;
        await WaitUntilAsync(() => healed = sut.RunAsync(Broken, "test", () => Task.FromResult(1)).Result.Succeeded);
        healed.Should().BeTrue("the circuit is closed as soon as the user is back, not after 60 s");
    }

    [Fact]
    public async Task ATimeout_AlsoAsksForTheUserToBeEnsured_AtMostOncePerMinute()
    {
        var systemContext = Substitute.For<ISystemContext>();
        systemContext.EnsureTenantDatabaseUserAsync("meshmaker").Returns(TenantDatabaseUserEnsureResult.AlreadyPresent);
        var sut = CreateHealingSut(systemContext);

        await sut.RunAsync<int>(Broken, "test", () => new TaskCompletionSource<int>().Task);
        await WaitUntilAsync(() => systemContext.ReceivedCalls().Any());
        _time.Advance(TimeSpan.FromSeconds(61)); // circuit half-open, a second failure
        await sut.RunAsync<int>(Broken, "test", () => new TaskCompletionSource<int>().Task);
        await WaitUntilAsync(() => systemContext.ReceivedCalls().Count() >= 2);

        await systemContext.Received(2).EnsureTenantDatabaseUserAsync("meshmaker");
    }

    [Fact]
    public async Task AFailureThatIsNotAboutTheUser_DoesNotTouchTheAdminConnection()
    {
        var systemContext = Substitute.For<ISystemContext>();
        var sut = CreateHealingSut(systemContext);

        await sut.RunAsync<int>(Broken, "test", () => throw new InvalidOperationException("collection missing"));
        await Task.Delay(100, TestContext.Current.CancellationToken);

        await systemContext.DidNotReceive().EnsureTenantDatabaseUserAsync(Arg.Any<string>());
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
