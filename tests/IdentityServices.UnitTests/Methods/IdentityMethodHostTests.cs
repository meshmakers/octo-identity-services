using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.ConstructionKit.Contracts.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
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
            .And.NotContain(SystemIdentityCkIds.UserSetPasswordMethodId)
            .And.NotContain(SystemIdentityCkIds.UserResetPasswordMethodId,
                "no handler is hosted, so the gateway answers METHOD_HANDLER_NOT_AVAILABLE (AB#7774)");
    }

    [Fact]
    public void SwitchOff_TheRoleGroupAndDataPermissionMethodsAreStillSelected_TheyCarryNoSecret()
    {
        var selected = IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions());

        selected.Select(h => h.MethodId).Should().BeEquivalentTo(
            SystemIdentityCkIds.UserSetRolesMethodId, SystemIdentityCkIds.UserAddRoleMethodId,
            SystemIdentityCkIds.UserRemoveRoleMethodId, SystemIdentityCkIds.UserDisableTwoFactorMethodId,
            SystemIdentityCkIds.UserMergeMethodId,
            SystemIdentityCkIds.GroupAddMemberMethodId,
            SystemIdentityCkIds.GroupRemoveMemberMethodId, SystemIdentityCkIds.GroupSetRolesMethodId,
            SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId);
        selected.Should().OnlyContain(h => !h.CarriesSecret);
    }

    [Fact]
    public void SwitchOn_ChangePasswordIsSelected()
    {
        var selected = IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true });

        selected.Select(h => h.MethodId).Should().Contain(SystemIdentityCkIds.UserChangePasswordMethodId)
            .And.Contain(SystemIdentityCkIds.UserSetPasswordMethodId)
            .And.Contain(SystemIdentityCkIds.UserResetPasswordMethodId);
    }

    [Fact]
    public void UserCreateUser_CarriesASecret_AndIsSelectedOnlyWithTheSwitch()
    {
        // AB#7777: the optional initial password is sensitive, so the whole method waits for the switch (also invitations).
        IdentityMethodHost.Handlers.Should().ContainSingle(h => h.MethodId == SystemIdentityCkIds.UserCreateUserMethodId)
            .Which.CarriesSecret.Should().BeTrue();
        IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions()).Select(h => h.MethodId).Should()
            .NotContain(SystemIdentityCkIds.UserCreateUserMethodId);
        IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true })
            .Select(h => h.MethodId).Should().Contain(SystemIdentityCkIds.UserCreateUserMethodId);
    }

    [Fact]
    public void SwitchOff_ThePasswordMethodsWithARestFacade_AreRegisteredLocalOnly()
    {
        // AB#8413: POST users and POST users/ResetPassword call these methods in-process; AB#8414: so do the account pages'
        // api/manage/change-password and set-password. With the switch off they are registered local only (not announced,
        // no queue), so the gateway still answers METHOD_HANDLER_NOT_AVAILABLE.
        IdentityMethodHost.SelectLocalOnlyHandlers(new IdentityMethodsOptions()).Select(h => h.MethodId).Should()
            .BeEquivalentTo(SystemIdentityCkIds.UserCreateUserMethodId, SystemIdentityCkIds.UserResetPasswordMethodId,
                SystemIdentityCkIds.UserChangePasswordMethodId, SystemIdentityCkIds.UserSetPasswordMethodId);
        IdentityMethodHost.SelectLocalOnlyHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true }).Should()
            .BeEmpty("with the switch on they are offered on the bus (SelectHandlers) and called in-process from there");
    }

    [Fact]
    public void SwitchOff_TheClientSecretMethods_StayUnregistered()
    {
        // No REST facade calls them yet: neither on the bus nor local only.
        var off = new IdentityMethodsOptions();
        var registered = IdentityMethodHost.SelectHandlers(off).Concat(IdentityMethodHost.SelectLocalOnlyHandlers(off))
            .Select(h => h.MethodId).ToList();

        registered.Should().NotContain([
            SystemIdentityCkIds.ClientAddSecretMethodId, SystemIdentityCkIds.ClientRemoveSecretMethodId
        ]);
    }

    [Fact]
    public void OnlySecretCarryingMethods_AreMarkedAsLocalOnlyFacades_AndNoMethodIsInBothLists()
    {
        IdentityMethodHost.Handlers.Where(h => h.ServesRestFacade).Should().OnlyContain(h => h.CarriesSecret,
            "a method without a secret is offered on the bus anyway, and the REST facade calls it in-process from there");
        foreach (var options in new[] { new IdentityMethodsOptions(), new IdentityMethodsOptions { EnablePasswordMethods = true } })
        {
            IdentityMethodHost.SelectHandlers(options).Select(h => h.MethodId).Should()
                .NotIntersectWith(IdentityMethodHost.SelectLocalOnlyHandlers(options).Select(h => h.MethodId),
                    "a method is registered for the bus or local only, never both (the start-up validation refuses it)");
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheRowsRegisterTheirHandler_OnTheBusWithHandle_AndLocalOnlyWithHandleLocalOnly(bool localOnly)
    {
        var builder = new RecordingRegistrationBuilder();

        foreach (var row in IdentityMethodHost.Handlers)
        {
            (localOnly ? row.RegisterLocalOnly : row.Register)(builder);
        }

        builder.Calls.Should().Equal(IdentityMethodHost.Handlers.Select(h =>
            (localOnly ? "HandleLocalOnly" : "Handle", h.MethodId, h.HandlerType)));
    }

    [Fact]
    public void SwitchOff_TheHostIsAddedWithTheLocalOnlyHandlers()
    {
        var services = new ServiceCollection();
        var off = new IdentityMethodsOptions();

        IdentityMethodHost.AddIdentityCkMethodHost(services, [],
            IdentityMethodHost.SelectLocalOnlyHandlers(off)).Should().BeTrue("a local-only handler alone is hosted");

        services.Should().Contain(d => d.ServiceType == typeof(UserResetPasswordHandler));
        services.Should().Contain(d => d.ServiceType == typeof(UserCreateUserHandler));
    }

    [Fact]
    public void ClientSecretMethods_CarryASecret_AndAreSelectedOnlyWithTheSwitch()
    {
        string[] secretMethods = [SystemIdentityCkIds.ClientAddSecretMethodId, SystemIdentityCkIds.ClientRemoveSecretMethodId];

        IdentityMethodHost.Handlers.Where(h => secretMethods.Contains(h.MethodId)).Should().HaveCount(2)
            .And.OnlyContain(h => h.CarriesSecret, "AddSecret has a sensitive result, RemoveSecret a sensitive parameter (AB#7780)");
        IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions()).Select(h => h.MethodId).Should()
            .NotContain(secretMethods);
        IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true })
            .Select(h => h.MethodId).Should().Contain(secretMethods);
    }

    // AB#5861: SecretManagement (REST parity with IdentitySecretAdministrationPolicy); in the staged Warn mode the
    // previous roles still pass (logged), in Enforce only SecretManagement. The write scope is always required.
    [Theory]
    [InlineData(new[] { "SecretManagement" }, new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Enforce, IdentityApiRoleDecision.Allowed)]
    [InlineData(new[] { "secretmanagement" }, new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Warn, IdentityApiRoleDecision.Allowed)]
    [InlineData(new[] { "TenantManagement" }, new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Warn, IdentityApiRoleDecision.AllowedByStagedWarn)]
    [InlineData(new[] { "usermanagement" }, new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Warn, IdentityApiRoleDecision.AllowedByStagedWarn)]
    [InlineData(new[] { "TenantManagement" }, new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Enforce, IdentityApiRoleDecision.Denied)]
    [InlineData(new[] { "UserManagement" }, new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Enforce, IdentityApiRoleDecision.Denied)]
    [InlineData(new[] { "SecretManagement" }, new[] { "octo_api.read_only" }, IdentityApiRoleEnforcementMode.Warn, IdentityApiRoleDecision.Denied)]
    [InlineData(new[] { "AdminPanelManagement" }, new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Warn, IdentityApiRoleDecision.Denied)]
    [InlineData(new string[0], new[] { "octo_api" }, IdentityApiRoleEnforcementMode.Warn, IdentityApiRoleDecision.Denied)]
    public void ClientSecretCaller_NeedsTheWriteScopeAndSecretManagement_StagedBySecretManagementRoleEnforcement(
        string[] roles, string[] scopes, IdentityApiRoleEnforcementMode secretMode, IdentityApiRoleDecision expected)
    {
        var options = new IdentityApiAuthorizationOptions { SecretManagementRoleEnforcement = secretMode };

        ClientSecretMethodHandlerBase.DecideClientSecretCaller(new CkMethodPrincipal("u", roles, scopes), options)
            .Should().Be(expected);
        ClientSecretMethodHandlerBase.DecideClientSecretCaller(null, options).Should().Be(IdentityApiRoleDecision.Denied);
    }

    [Fact]
    public void ClientSecretCaller_TheClusterWideWarnSwitch_AlsoRelaxesToThePreviousRoles_ButNotFurther()
    {
        var options = new IdentityApiAuthorizationOptions
        {
            RoleEnforcement = IdentityApiRoleEnforcementMode.Warn,
            SecretManagementRoleEnforcement = IdentityApiRoleEnforcementMode.Enforce
        };

        ClientSecretMethodHandlerBase.DecideClientSecretCaller(new CkMethodPrincipal("u", ["TenantManagement"], ["octo_api"]),
            options).Should().Be(IdentityApiRoleDecision.AllowedByStagedWarn);
        ClientSecretMethodHandlerBase.DecideClientSecretCaller(new CkMethodPrincipal("u", ["DashboardViewer"], ["octo_api"]),
            options).Should().Be(IdentityApiRoleDecision.Denied);
    }

    [Fact]
    public void TheSwitchIsReadFromTheConfigurationSection()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Methods:Identity:EnablePasswordMethods"] = "true" }).Build();

        IdentityMethodHost.ReadOptions(configuration).EnablePasswordMethods.Should().BeTrue();
    }

    [Fact]
    public void TheStartupValidation_NeedsNoIdentityWorkaround_WithTheDefaultConfiguration()
    {
        // The SDK normalizes the tenant id of the start-up validation itself (AB#7912): the host adds no tenant list, so a default
        // installation ("OctoSystem") validates its methods against the CK cache of the lower case system tenant without configuration.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.Configure<OctoSystemConfiguration>(c => c.SystemTenantId = "OctoSystem");
        IdentityMethodHost.AddIdentityCkMethodHost(services,
            IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true }))
            .Should().BeTrue();

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IOptions<CkMethodHandlerOptions>>().Value.ValidationTenantIds.Should().BeEmpty();
    }

    [Fact]
    public void TheStartupValidation_LooksTheMethodUpInTheLowerCaseCacheOfTheDefaultSystemTenant()
    {
        // The real definition source of the resolved SDK package, built from the host registration with the default
        // "OctoSystem": it must ask the CK cache for the lower case key (AB#7912), otherwise the service would not start.
        // Only the lower-case key is loaded: since AB#8969 the source no longer skips an unloaded tenant but throws
        // ("cache not loaded"), so a lookup under the mixed-case key fails the test as well.
        var cache = Substitute.For<ICkCacheService>();
        cache.IsTenantLoaded("octosystem").Returns(true);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.AddSingleton(cache);
        services.Configure<OctoSystemConfiguration>(c => c.SystemTenantId = "OctoSystem");
        IdentityMethodHost.AddIdentityCkMethodHost(services,
            IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true }));
        var sourceType = typeof(CkMethodHandlerOptions).Assembly
            .GetType("Meshmakers.Octo.Services.Methods.Handlers.ICkMethodDefinitionSource", throwOnError: true)!;
        using var provider = services.BuildServiceProvider();
        var source = provider.GetRequiredService(sourceType);

        ((IReadOnlyList<string>)sourceType.GetProperty("TenantIds")!.GetValue(source)!).Should().Equal("octosystem");
        sourceType.GetMethod("Find")!.Invoke(source, ["System.Identity/User.SetRoles"]);
        cache.Received().IsTenantLoaded("octosystem");
        cache.DidNotReceive().IsTenantLoaded("OctoSystem");
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
    public async Task Audit_ExtraDetails_AreWrittenAfterTheStandardOnes()
    {
        var events = Substitute.For<IEventRepository>();
        IReadOnlyCollection<KeyValuePair<string, string>>? details = null;
        await events.StoreEventAsync("t1", RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Information,
            Arg.Any<string>(), "Identity.Method", Arg.Do<IReadOnlyCollection<KeyValuePair<string, string>>>(d => details = d));

        await new IdentityMethodAuditWriter(events, NullLogger<IdentityMethodAuditWriter>.Instance)
            .RecordAsync("t1", SystemIdentityCkIds.UserSetRolesMethodId, Guid.NewGuid(), "user-1", "admin-1",
                IdentityMethodAuditWriter.SuccessOutcome,
                new Dictionary<string, string> { ["rolesBefore"] = "A", ["rolesAfter"] = "A,B" });

        details!.Should().Contain(new KeyValuePair<string, string>("rolesBefore", "A"))
            .And.Contain(new KeyValuePair<string, string>("rolesAfter", "A,B"))
            .And.Contain(new KeyValuePair<string, string>("callerSubject", "admin-1"));
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
                IdentityMethodAuditWriter.SuccessOutcome, new Dictionary<string, string> { ["lockoutLifted"] = "true" });

        details!.Should().Contain(new KeyValuePair<string, string>("lockoutLifted", "true"));
        details.Select(d => d.Key).Should().Contain(["methodId", "outcome", "targetRtId", "callerSubject"]);
    }

    private sealed class RecordingRegistrationBuilder : ICkMethodHandlerRegistrationBuilder
    {
        public List<(string Kind, string MethodId, Type HandlerType)> Calls { get; } = [];

        public ICkMethodHandlerRegistrationBuilder Handle<THandler>(string qualifiedMethodId)
            where THandler : class, ICkMethodHandler
        {
            Calls.Add(("Handle", qualifiedMethodId, typeof(THandler)));
            return this;
        }

        public ICkMethodHandlerRegistrationBuilder HandleLocalOnly<THandler>(string qualifiedMethodId)
            where THandler : class, ICkMethodHandler
        {
            Calls.Add(("HandleLocalOnly", qualifiedMethodId, typeof(THandler)));
            return this;
        }
    }
}
