using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Methods;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Methods;

/// <summary>AB#5672: the method host of the identity service, the production gate and the audit record.</summary>
public class IdentityMethodHostTests
{
    [Fact]
    public void TheSwitchDefaultsToOff()
    {
        new IdentityMethodsOptions().EnablePasswordMethods.Should().BeFalse();
        IdentityMethodHost.ReadOptions(new ConfigurationBuilder().Build()).EnablePasswordMethods.Should().BeFalse();
    }

    [Fact]
    public void SwitchOff_NoHandlerOfASecretCarryingMethodIsSelected()
    {
        var selected = IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions());

        selected.Should().NotContain(h => h.CarriesSecret);
        selected.Select(h => h.MethodId).Should().NotContain(SystemIdentityCkIds.UserChangePasswordMethodId)
            .And.NotContain(SystemIdentityCkIds.UserResetPasswordMethodId,
                "no handler is hosted, so the gateway answers METHOD_HANDLER_NOT_AVAILABLE (AB#7774)");
    }

    [Fact]
    public void SwitchOn_ChangePasswordIsSelected()
    {
        var selected = IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true });

        selected.Select(h => h.MethodId).Should().Contain(SystemIdentityCkIds.UserChangePasswordMethodId)
            .And.Contain(SystemIdentityCkIds.UserResetPasswordMethodId);
    }

    [Fact]
    public void TheSwitchIsReadFromTheConfigurationSection()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Methods:Identity:EnablePasswordMethods"] = "true" }).Build();

        IdentityMethodHost.ReadOptions(configuration).EnablePasswordMethods.Should().BeTrue();
    }

    [Fact]
    public void TheStartupValidation_NamesTheNormalizedSystemTenantId()
    {
        // The CK cache is keyed by the lower case tenant id; "OctoSystem" as configured would miss it and stop the service.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.Configure<OctoSystemConfiguration>(c => c.SystemTenantId = "OctoSystem");
        IdentityMethodHost.AddIdentityCkMethodHost(services,
            IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true }))
            .Should().BeTrue();

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IOptions<CkMethodHandlerOptions>>().Value.ValidationTenantIds
            .Should().Equal("octosystem");
    }

    [Fact]
    public void WithoutASelectedHandler_NothingIsHosted()
    {
        var services = new ServiceCollection();

        IdentityMethodHost.AddIdentityCkMethodHost(services, []).Should().BeFalse();

        services.Any(d => d.ServiceType == typeof(IMethodTenantAccessor)).Should().BeFalse();
    }

    [Fact]
    public async Task Audit_WritesIdentifiersAndTheOutcome_NeverAValue()
    {
        var events = Substitute.For<IEventRepository>();
        IReadOnlyCollection<KeyValuePair<string, string>>? details = null;
        await events.StoreEventAsync("t1", RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Warning,
            Arg.Any<string>(), "Identity.Method", Arg.Do<IReadOnlyCollection<KeyValuePair<string, string>>>(d => details = d));

        await new IdentityMethodAuditWriter(events, NullLogger<IdentityMethodAuditWriter>.Instance)
            .RecordAsync("t1", SystemIdentityCkIds.UserChangePasswordMethodId, Guid.NewGuid(), "user-1", "user-1",
                "CURRENT_PASSWORD_INVALID");

        await events.Received(1).StoreEventAsync("t1", RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Warning,
            Arg.Is<string>(m => m.Contains("CURRENT_PASSWORD_INVALID")), "Identity.Method",
            Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>>());
        details!.Select(d => d.Key).Should().BeEquivalentTo("methodId", "invocationId", "outcome", "targetRtId",
            "callerSubject");
    }

    [Fact]
    public async Task Audit_Success_IsAnInformationEvent()
    {
        var events = Substitute.For<IEventRepository>();

        await new IdentityMethodAuditWriter(events, NullLogger<IdentityMethodAuditWriter>.Instance)
            .RecordAsync("t1", "m", Guid.NewGuid(), null, null, IdentityMethodAuditWriter.SuccessOutcome);

        await events.Received(1).StoreEventAsync("t1", RtEventSourcesEnum.IdentityService,
            RtEventLevelsEnum.Information, Arg.Any<string>(), "Identity.Method",
            Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>>());
    }

    [Fact]
    public async Task Audit_AFailingWrite_NeverFailsTheCall()
    {
        var events = Substitute.For<IEventRepository>();
        events.StoreEventAsync(default!, default, default, default!, default, default)
            .ReturnsForAnyArgs(Task.FromException(new InvalidOperationException("db down")));

        var act = () => new IdentityMethodAuditWriter(events, NullLogger<IdentityMethodAuditWriter>.Instance)
            .RecordAsync("t1", "m", Guid.NewGuid(), "x", "y", "SUCCESS");

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Audit_WritesTheMethodSpecificDetails()
    {
        var events = Substitute.For<IEventRepository>();
        IReadOnlyCollection<KeyValuePair<string, string>>? details = null;
        await events.StoreEventAsync("t1", RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Information,
            Arg.Any<string>(), "Identity.Method", Arg.Do<IReadOnlyCollection<KeyValuePair<string, string>>>(d => details = d));

        await new IdentityMethodAuditWriter(events, NullLogger<IdentityMethodAuditWriter>.Instance)
            .RecordAsync("t1", SystemIdentityCkIds.UserResetPasswordMethodId, Guid.NewGuid(), "user-1", "admin-1",
                IdentityMethodAuditWriter.SuccessOutcome, [new("lockoutLifted", "true")]);

        details!.Should().Contain(new KeyValuePair<string, string>("lockoutLifted", "true"));
        details.Select(d => d.Key).Should().Contain(["methodId", "outcome", "targetRtId", "callerSubject"]);
    }
}
