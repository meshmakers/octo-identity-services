using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services.SourceTenantGrants;
using Microsoft.Extensions.Options;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SourceTenantGrants;

/// <summary>AB#8341 — the lookup limit per caller and target tenant (sliding window, exact wait time).</summary>
public class SourceUserLookupRateLimiterTests
{
    [Fact]
    public void Defaults_AreTwentyPerTenMinutes()
    {
        var options = new SourceUserLookupRateLimitOptions();

        options.Enabled.Should().BeTrue();
        options.PermitLimit.Should().Be(20);
        options.Window.Should().Be(TimeSpan.FromMinutes(10));
    }

    [Fact]
    public void LimitExceeded_AnswersTheSecondsUntilTheOldestLookupLeavesTheWindow()
    {
        var clock = new ManualClock();
        var limiter = Create(clock, permits: 3, window: TimeSpan.FromMinutes(10));

        limiter.TryAcquire("alice", "t1").Should().BeNull();
        clock.Advance(TimeSpan.FromMinutes(2));
        limiter.TryAcquire("alice", "t1").Should().BeNull();
        limiter.TryAcquire("alice", "t1").Should().BeNull();

        limiter.TryAcquire("alice", "t1").Should().Be(480, "the first lookup leaves the window 8 minutes from now");
        clock.Advance(TimeSpan.FromSeconds(479.5));
        limiter.TryAcquire("alice", "t1").Should().Be(1, "never 0");
        clock.Advance(TimeSpan.FromSeconds(0.5));
        limiter.TryAcquire("alice", "t1").Should().BeNull("the first lookup has left the window");
        limiter.TryAcquire("alice", "t1").Should().Be(120);
    }

    [Fact]
    public void RefusedLookups_DoNotExtendTheWait()
    {
        var clock = new ManualClock();
        var limiter = Create(clock, permits: 1, window: TimeSpan.FromMinutes(1));

        limiter.TryAcquire("alice", "t1").Should().BeNull();
        for (var i = 0; i < 10; i++)
        {
            limiter.TryAcquire("alice", "t1").Should().NotBeNull();
        }

        clock.Advance(TimeSpan.FromMinutes(1));
        limiter.TryAcquire("alice", "t1").Should().BeNull();
    }

    [Fact]
    public void Partitions_ArePerCallerAndTargetTenant_TenantCaseInsensitive()
    {
        var limiter = Create(new ManualClock(), permits: 1, window: TimeSpan.FromMinutes(10));

        limiter.TryAcquire("alice", "Tenant-A").Should().BeNull();
        limiter.TryAcquire("alice", "tenant-a").Should().NotBeNull("tenant ids are case-insensitive");
        limiter.TryAcquire("bob", "tenant-a").Should().BeNull("another caller has its own budget");
        limiter.TryAcquire("alice", "tenant-b").Should().BeNull("another target tenant has its own budget");
    }

    [Fact]
    public void Disabled_NeverLimits()
    {
        var limiter = new SourceUserLookupRateLimiter(Options.Create(new OctoIdentityServicesOptions
        {
            SourceUserLookupRateLimit = new SourceUserLookupRateLimitOptions { Enabled = false, PermitLimit = 1 }
        }), new ManualClock());

        for (var i = 0; i < 5; i++)
        {
            limiter.TryAcquire("alice", "t1").Should().BeNull();
        }
    }

    [Fact]
    public async Task DefaultPolicy_PermitsNobody()
        => (await new DenyNonAncestorsSourceTenantGrantPolicy().IsPermittedAsync("meshmakers", "customer", TestContext.Current.CancellationToken))
            .Should().BeFalse();

    private static SourceUserLookupRateLimiter Create(TimeProvider clock, int permits, TimeSpan window)
        => new(Options.Create(new OctoIdentityServicesOptions
        {
            SourceUserLookupRateLimit = new SourceUserLookupRateLimitOptions { PermitLimit = permits, Window = window }
        }), clock);

    private sealed class ManualClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 11, 6, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
