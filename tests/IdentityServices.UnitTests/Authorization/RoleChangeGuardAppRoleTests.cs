using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#8564: the grant rule of the role change guard. A caller holding <c>UserManagement</c> may grant app roles (built-in
///     roles of a blueprint other than <c>System.Identity.Bootstrap</c>) it does not hold; platform roles must still be held,
///     also inside a group that mixes both. Without <c>UserManagement</c> nothing changes. The group, membership and nesting
///     paths are covered end to end by <c>AppRoleGrantTests</c>.
/// </summary>
public class RoleChangeGuardAppRoleTests
{
    private const string UserManagement = "UserManagement";
    private const string Platform = "StreamDataAdmin";
    private const string App = "EnergyCommunityManagement";
    private const string Custom = "MyCustomRole";

    private readonly RoleManager<RtRole> _roleManager =
        Substitute.For<RoleManager<RtRole>>(Substitute.For<IRoleStore<RtRole>>(), null, null, null, null);
    private readonly IPlatformRoleCatalog _platformRoles = Substitute.For<IPlatformRoleCatalog>();
    private readonly CapturingLogger _logger = new();
    private readonly RoleChangeGuard _sut;

    public RoleChangeGuardAppRoleTests()
    {
        AddRole(UserManagement, builtIn: true, platform: true);
        AddRole(Platform, builtIn: true, platform: true);
        AddRole(App, builtIn: true, platform: false);
        AddRole(Custom, builtIn: false, platform: false);

        var userManager = Substitute.For<UserManager<RtUser>>(Substitute.For<IUserStore<RtUser>>(), null, null, null,
            null, null, null, null, null);
        _sut = new RoleChangeGuard(userManager, _roleManager, Substitute.For<IGroupStore>(),
            Substitute.For<IGroupRoleResolver>(), Substitute.For<IUserStore<RtUser>>(),
            Substitute.For<IExternalTenantUserMappingStore>(), Substitute.For<ICrossTenantShadowUserChainResolver>(),
            _platformRoles, Substitute.For<IOctoClientStore>(), _logger);
    }

    private void AddRole(string name, bool builtIn, bool platform)
    {
        var role = new RtRoleBuilder().WithName(name).Build();
        role.RtId = OctoObjectId.GenerateNewId();
        role.RtWellKnownName = builtIn ? name : null;
        _roleManager.FindByNameAsync(name).Returns(role);
        _platformRoles.IsPlatformRole(role).Returns(platform);
    }

    private static RoleChangeCaller Caller(params string[] roles) => new(null, "tenant-owner", roles);

    [Fact]
    public async Task Administrator_MayGrantAnAppRoleItDoesNotHold_AndTheGrantIsLoggedAtInfo()
    {
        var decision = await _sut.EvaluateGrantAsync(Caller(UserManagement), [App],
            TestContext.Current.CancellationToken, "client ec-norole");

        decision.IsAllowed.Should().BeTrue();
        decision.AppRolesNotHeld.Should().Equal(App);
        _logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Information &&
                                                   e.Message.Contains("app-role-grant") &&
                                                   e.Message.Contains("client tenant-owner") &&
                                                   e.Message.Contains("client ec-norole") &&
                                                   e.Message.Contains(App));
    }

    [Fact]
    public async Task Administrator_IsRefusedAPlatformRoleItDoesNotHold()
    {
        var decision = await _sut.EvaluateGrantAsync(Caller(UserManagement), [Platform],
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.RoleNotHeld);
        decision.RoleNames.Should().Equal(Platform);
        _logger.Entries.Should().BeEmpty();
    }

    [Fact]
    public async Task Administrator_GrantingAppAndPlatformRoles_IsRefusedOnlyForThePlatformRole()
    {
        var decision = await _sut.EvaluateGrantAsync(Caller(UserManagement), [App, Platform, Custom],
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.RoleNotHeld);
        decision.RoleNames.Should().Equal(Platform);
        decision.AppRolesNotHeld.Should().BeEmpty();
    }

    [Fact]
    public async Task Administrator_HoldingThePlatformRole_MayGrantItTogetherWithAnAppRole()
    {
        var decision = await _sut.EvaluateGrantAsync(Caller(UserManagement, Platform), [App, Platform, Custom],
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
        decision.AppRolesNotHeld.Should().Equal(App);
    }

    [Fact]
    public async Task CallerWithoutUserManagement_IsRefusedAnAppRoleItDoesNotHold()
    {
        var decision = await _sut.EvaluateGrantAsync(Caller("TenantManagement"), [App],
            TestContext.Current.CancellationToken);

        decision.Reason.Should().Be(RoleChangeReasons.RoleNotHeld);
        decision.RoleNames.Should().Equal(App);
        _logger.Entries.Should().BeEmpty();
    }

    [Fact]
    public async Task HeldAndCustomRoles_AreAllowed_WithoutAnAppRoleLog()
    {
        var decision = await _sut.EvaluateGrantAsync(Caller(UserManagement, App), [App, Custom],
            TestContext.Current.CancellationToken);

        decision.IsAllowed.Should().BeTrue();
        decision.AppRolesNotHeld.Should().BeEmpty();
        _logger.Entries.Should().BeEmpty();
    }

    private sealed class CapturingLogger : ILogger<RoleChangeGuard>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add((logLevel, formatter(state, exception)));
    }
}
