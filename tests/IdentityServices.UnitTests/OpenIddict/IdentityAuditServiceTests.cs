using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace IdentityServices.UnitTests.OpenIddict;

/// <summary>
///     AB#8342: <see cref="IIdentityAuditService" /> keeps its failure auditing unchanged and gains explicit-tenant
///     information and warning events. No method ever throws into the caller.
/// </summary>
public class IdentityAuditServiceTests
{
    private readonly IEventRepository _events = Substitute.For<IEventRepository>();
    private readonly IHttpContextAccessor _accessor = Substitute.For<IHttpContextAccessor>();

    private IdentityAuditService CreateSut() => new(_events, _accessor, NullLogger<IdentityAuditService>.Instance);

    private void WireRequestTenant(string? tenantId)
    {
        var context = new DefaultHttpContext();
        if (tenantId != null)
        {
            context.Items[InfrastructureCommon.TenantIdName] = tenantId;
        }

        _accessor.HttpContext.Returns(context);
    }

    // ------------------------------------------------------------------ regression: failures

    [Fact]
    public async Task StoreFailure_WithRequestTenant_WritesOneErrorEventIntoThatTenant()
    {
        WireRequestTenant("tenant-a");

        await CreateSut().StoreFailureAsync("Token Exchange Failure", "denied");

        await _events.Received(1).StoreErrorEvent("tenant-a", RtEventSourcesEnum.IdentityService,
            "[Token Exchange Failure] denied", Arg.Any<RtEntityId?>());
        await _events.DidNotReceiveWithAnyArgs().StoreSystemErrorEvent(default, default!, default);
        await _events.DidNotReceiveWithAnyArgs().StoreEventAsync(default!, default, default, default!, default,
            default, default);
    }

    [Fact]
    public async Task StoreFailure_WithoutRequestTenant_WritesOneSystemErrorEvent()
    {
        WireRequestTenant(null);

        await CreateSut().StoreFailureAsync("Login Failure", "bad password");

        await _events.Received(1).StoreSystemErrorEvent(RtEventSourcesEnum.IdentityService,
            "[Login Failure] bad password", Arg.Any<RtEntityId?>());
        await _events.DidNotReceiveWithAnyArgs().StoreErrorEvent(default!, default, default!, default);
    }

    [Fact]
    public async Task StoreFailure_RepositoryThrows_DoesNotThrow()
    {
        WireRequestTenant("tenant-a");
        _events.StoreErrorEvent(default!, default, default!, default).ReturnsForAnyArgs(
            Task.FromException(new InvalidOperationException("db down")));

        var act = () => CreateSut().StoreFailureAsync("X", "y");

        await act.Should().NotThrowAsync();
    }

    // ------------------------------------------------------------------ explicit tenant

    [Fact]
    public async Task StoreInfo_WritesIntoTheExplicitTenant_NotTheRequestTenant_WithCategoryAndDetails()
    {
        WireRequestTenant("request-tenant");
        IReadOnlyCollection<KeyValuePair<string, string>>? captured = null;
        _events.StoreEventAsync("source-tenant", RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Information,
                "[CrossTenantGrantCreated] granted", "CrossTenantGrantCreated",
                Arg.Do<IReadOnlyCollection<KeyValuePair<string, string>>?>(d => captured = d), Arg.Any<RtEntityId?>())
            .Returns(Task.CompletedTask);

        await CreateSut().StoreInfoAsync("source-tenant", "CrossTenantGrantCreated", "granted",
            new Dictionary<string, string> { ["mappingId"] = "m1" });

        await _events.Received(1).StoreEventAsync("source-tenant", RtEventSourcesEnum.IdentityService,
            RtEventLevelsEnum.Information, "[CrossTenantGrantCreated] granted", "CrossTenantGrantCreated",
            Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>());
        captured.Should().BeEquivalentTo(new[] { new KeyValuePair<string, string>("mappingId", "m1") });
        await _events.DidNotReceiveWithAnyArgs().StoreErrorEvent(default!, default, default!, default);
    }

    [Fact]
    public async Task StoreWarning_WritesAWarningEvent()
    {
        await CreateSut().StoreWarningAsync("t", "CrossTenantExchangeRefused", "refused");

        await _events.Received(1).StoreEventAsync("t", RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Warning,
            "[CrossTenantExchangeRefused] refused", "CrossTenantExchangeRefused",
            Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task StoreInfo_WithoutTenant_WritesNothing_AndDoesNotThrow(string tenantId)
    {
        var act = () => CreateSut().StoreInfoAsync(tenantId, "E", "m");

        await act.Should().NotThrowAsync();
        await _events.DidNotReceiveWithAnyArgs().StoreEventAsync(default!, default, default, default!, default,
            default, default);
    }

    [Fact]
    public async Task StoreInfo_RepositoryThrows_DoesNotThrow()
    {
        _events.StoreEventAsync(default!, default, default, default!, default, default, default)
            .ThrowsAsyncForAnyArgs(new InvalidOperationException("db down"));

        var act = () => CreateSut().StoreInfoAsync("t", "E", "m");

        await act.Should().NotThrowAsync();
    }
}
