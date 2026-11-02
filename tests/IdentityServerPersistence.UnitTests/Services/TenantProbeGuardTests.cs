using System.Net;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using MongoDB.Driver.Core.Clusters;
using MongoDB.Driver.Core.Connections;
using MongoDB.Driver.Core.Servers;
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

    private TenantProbeGuard CreateSut(TimeSpan? timeout = null, TimeSpan? open = null) =>
        new(Options.Create(new TenantProbeGuardOptions
            {
                ProbeTimeout = timeout ?? TimeSpan.FromMilliseconds(200),
                OpenDuration = open ?? TimeSpan.FromSeconds(60)
            }),
            Options.Create(new OctoSystemConfiguration { DatabaseUser = "octo-system-ds-user-{0}" }), _logger);

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
        var sut = CreateSut(open: TimeSpan.FromMilliseconds(300));
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

        await Task.Delay(400, TestContext.Current.CancellationToken);

        (await sut.RunAsync(Broken, "test", Failing)).Succeeded.Should().BeFalse();
        calls.Should().Be(2, "after the open duration exactly one request probes again");
    }

    [Fact]
    public async Task ARecoveredTenant_ClosesTheCircuit()
    {
        var sut = CreateSut(open: TimeSpan.FromMilliseconds(100));
        await sut.RunAsync<int>(Broken, "test", () => throw AuthFailure());
        await Task.Delay(200, TestContext.Current.CancellationToken);

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
}
