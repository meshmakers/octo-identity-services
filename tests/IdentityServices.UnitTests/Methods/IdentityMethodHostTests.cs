using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.Extensions.Configuration;
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
        selected.Select(h => h.MethodId).Should().NotContain(SystemIdentityCkIds.UserChangePasswordMethodId);
    }

    [Fact]
    public void SwitchOn_ChangePasswordIsSelected()
    {
        var selected = IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true });

        selected.Select(h => h.MethodId).Should().Contain(SystemIdentityCkIds.UserChangePasswordMethodId);
    }

    [Fact]
    public void TheSwitchIsReadFromTheConfigurationSection()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Methods:Identity:EnablePasswordMethods"] = "true" }).Build();

        IdentityMethodHost.ReadOptions(configuration).EnablePasswordMethods.Should().BeTrue();
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
}
