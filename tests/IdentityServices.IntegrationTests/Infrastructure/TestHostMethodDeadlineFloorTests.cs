using FluentAssertions;
using Meshmakers.Octo.Services.Methods;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     The test-host method deadline floor (<see cref="TestHostMethodDeadlineFloor" />): the factory host and its derived
///     hosts use it, it raises short CK timeouts to the floor, and it keeps longer ones and the "unknown method" answer of
///     the production resolver.
/// </summary>
public class TestHostMethodDeadlineFloorTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    private const string Tenant = "tenant";
    private const string Type = "System.Identity/User";
    private const string Method = "AddRole-1";

    [Fact]
    public void TheTestHostAndADerivedHost_ResolveTheMethodTimeoutThroughTheFloor()
    {
        Factory.Services.GetRequiredService<ICkMethodTimeoutResolver>().Should().BeOfType<TestHostMethodDeadlineFloor>();

        using var derived = Factory.WithWebHostBuilder(_ => { });
        derived.Services.GetRequiredService<ICkMethodTimeoutResolver>().Should().BeOfType<TestHostMethodDeadlineFloor>();
    }

    [Fact]
    public void AShortCkTimeout_IsRaisedToTheFloor_InTimeoutAndDeadline()
    {
        var now = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var sut = new TestHostMethodDeadlineFloor(new FixedResolver(TimeSpan.FromSeconds(15), true, now),
            new FixedTimeProvider(now));

        sut.GetTimeout(Tenant, Type, Method).Should().Be(TestHostMethodDeadlineFloor.Floor);
        sut.TryGetTimeout(Tenant, Type, Method, out var timeout).Should().BeTrue();
        timeout.Should().Be(TestHostMethodDeadlineFloor.Floor);
        sut.GetDeadlineUtc(Tenant, Type, Method).Should().Be(now.UtcDateTime + TestHostMethodDeadlineFloor.Floor);
    }

    [Fact]
    public void ALongerCkTimeout_IsKept()
    {
        var now = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var sut = new TestHostMethodDeadlineFloor(new FixedResolver(TimeSpan.FromSeconds(300), true, now),
            new FixedTimeProvider(now));

        sut.GetTimeout(Tenant, Type, Method).Should().Be(TimeSpan.FromSeconds(300));
        sut.GetDeadlineUtc(Tenant, Type, Method).Should().Be(now.UtcDateTime + TimeSpan.FromSeconds(300));
    }

    [Fact]
    public void AnUnknownMethod_StaysUnknown()
    {
        var now = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var sut = new TestHostMethodDeadlineFloor(new FixedResolver(TimeSpan.FromSeconds(15), false, now),
            new FixedTimeProvider(now));

        sut.TryGetTimeout(Tenant, Type, Method, out _).Should().BeFalse();
        sut.GetTimeout(Tenant, Type, Method).Should().Be(TestHostMethodDeadlineFloor.Floor);
    }

    private sealed class FixedResolver(TimeSpan timeout, bool known, DateTimeOffset now) : ICkMethodTimeoutResolver
    {
        public bool TryGetTimeout(string tenantId, string ckTypeId, string methodId, out TimeSpan value)
        {
            value = known ? timeout : default;
            return known;
        }

        public TimeSpan GetTimeout(string tenantId, string ckTypeId, string methodId) => timeout;

        public DateTime GetDeadlineUtc(string tenantId, string ckTypeId, string methodId) => now.UtcDateTime + timeout;
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
