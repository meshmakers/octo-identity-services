using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Methods.Handlers;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7778: <c>User.Merge-1</c> and the REST merge <c>POST {tenant}/v1/users/{userName}/merge</c> share one merge
///     (<see cref="IUserMergeService" />). Real MongoDB and the real identity host (the bus side of the method host is removed,
///     the test host has no broker); the handler runs in a fresh scope without an HTTP request, as on the bus, with the
///     principal the host validated. The parity tests build the same fixture twice, merge one through REST and one through the
///     method and compare the resulting state.
/// </summary>
public class UserMergeMethodTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";
    private static readonly string[] AdminRoles = [UserManagement];

    private readonly WebApplicationFactory<Program> _host;
    private readonly ConcurrentQueue<CapturedEvent> _events = new();
    private readonly CapturingLoggerProvider _logs = new();

    public UserMergeMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            foreach (var descriptor in services
                         .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                             or "CkMethodHandlerHeartbeatService").ToList())
            {
                services.Remove(descriptor);
            }

            services.AddLogging(l => l.AddProvider(_logs));
            var events = Substitute.For<IEventRepository>();
            events.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<RtEventLevelsEnum>(),
                    Arg.Any<string>(), Arg.Any<string?>(),
                    Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>())
                .Returns(call =>
                {
                    _events.Enqueue(new CapturedEvent(call.ArgAt<string>(3), call.ArgAt<string?>(4),
                        (call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                        .ToDictionary(p => p.Key, p => p.Value)));
                    return Task.CompletedTask;
                });
            services.RemoveAll<IEventRepository>();
            services.AddSingleton(events);
        }));
    }

    /// <summary>The derived host keeps file watchers (inotify instances); dispose it with the test class.</summary>
    public void Dispose() => _host.Dispose();

    [Fact]
    public void TheHandler_IsHostedWithoutThePasswordSwitch_BecauseItCarriesNoSecret()
    {
        using var scope = Factory.Services.CreateScope();
        scope.ServiceProvider.GetService<UserMergeHandler>().Should().NotBeNull(
            "the method has no sensitive parameter or result, so EnablePasswordMethods does not gate it");
    }

    [Fact]
    public async Task RestAndMethod_OnIdenticalFixtures_LeaveTheSameState()
    {
        var ct = TestContext.Current.CancellationToken;
        var restFixture = await NewFixtureAsync("rest");
        var methodFixture = await NewFixtureAsync("method");

        var response = await RestClient(Guid.NewGuid().ToString("N"), AdminRoles).PostAsJsonAsync(
            TenantApiUrl($"users/{restFixture.Target.UserName}/merge"),
            new { sourceUserName = restFixture.Source.UserName }, ct);
        var outcome = await MergeAsync(Admin(), methodFixture.Target.RtId.ToString(), methodFixture.Source.UserName, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        outcome.IsSuccess.Should().BeTrue(outcome.Failure?.Code);
        var restState = await SnapshotAsync(restFixture);
        var methodState = await SnapshotAsync(methodFixture);
        methodState.Should().BeEquivalentTo(restState, "REST and the method share one merge");

        // and that state is the documented one
        methodState.SourceExists.Should().BeFalse("the source user is deleted");
        methodState.TargetLogins.Should().BeEquivalentTo("Facebook:own", "Google:a", "Microsoft:b");
        methodState.LoginsResolveToTarget.Should().BeTrue("a sign-in with a moved login finds the target");
        methodState.TargetDirectRoles.Should().BeEquivalentTo(["TARGETROLE"],
            "roles of the source user are not transferred");
        methodState.TargetInSourceGroup.Should().BeFalse("group memberships of the source user are not transferred");
        methodState.ValidSourceTokens.Should().Be(0, "the refresh tokens of the source user are revoked");
        methodState.ValidTargetTokens.Should().Be(1, "the tokens of the target user are untouched");
    }

    [Fact]
    public async Task Method_Success_WritesOneAuditEvent_WithSourceAndCounts_AndNoTokenValue()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("audit");
        var admin = await CreateTestUserAsync(NewName("admin"));

        var outcome = await MergeAsync(Admin(admin), fixture.Target.RtId.ToString(), fixture.Source.UserName, ct);

        outcome.IsSuccess.Should().BeTrue();
        var audit = SingleAudit(fixture.Target.RtId.ToString());
        audit.Details["outcome"].Should().Be("SUCCESS");
        audit.Details["methodId"].Should().Be(SystemIdentityCkIds.UserMergeMethodId);
        audit.Details["callerSubject"].Should().Be(admin.RtId.ToString());
        audit.Details["sourceUserName"].Should().Be(fixture.Source.UserName);
        audit.Details["sourceRtId"].Should().Be(fixture.Source.RtId.ToString());
        audit.Details["transferredLogins"].Should().Be("2");
        audit.Details["revokedTokens"].Should().Be("1");
        audit.Details.Keys.Should().BeEquivalentTo("methodId", "invocationId", "outcome", "targetRtId", "callerSubject",
            "sourceUserName", "sourceRtId", "transferredLogins", "revokedTokens");
        _events.SelectMany(e => e.Details.Values).Concat(_events.Select(e => e.Message))
            .Should().NotContain(v => v.Contains(fixture.SourceTokenId), "no token is audited");
        _logs.Messages.Should().Contain(m => m.Contains("Sessions revoked") && m.Contains(fixture.Source.RtId.ToString()) &&
                                             m.Contains(admin.UserName!), "the revocation line names the acting user");
    }

    [Fact]
    public async Task Method_SameUser_IsCannotMergeIntoItself_AndNothingChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("self");

        var outcome = await MergeAsync(Admin(), fixture.Source.RtId.ToString(), fixture.Source.UserName, ct);

        outcome.Failure!.Code.Should().Be(UserMergeHandler.CannotMergeIntoItself);
        await AssertUnchangedAsync(fixture);
        SingleAudit(fixture.Source.RtId.ToString()).Details["outcome"].Should().Be(UserMergeHandler.CannotMergeIntoItself);
    }

    [Fact]
    public async Task Method_UnknownSource_IsSourceUserNotFound_AndRestAnswers404()
    {
        var ct = TestContext.Current.CancellationToken;
        var target = await CreateTestUserAsync(NewName("t"));
        var unknown = NewName("nobody");

        var outcome = await MergeAsync(Admin(), target.RtId.ToString(), unknown, ct);
        var response = await RestClient(Guid.NewGuid().ToString("N"), AdminRoles).PostAsJsonAsync(
            TenantApiUrl($"users/{target.UserName}/merge"), new { sourceUserName = unknown }, ct);

        outcome.Failure!.Code.Should().Be(UserMergeHandler.SourceUserNotFound);
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Method_MissingSourceUserName_IsValidationFailed(string? sourceUserName)
    {
        var target = await CreateTestUserAsync(NewName("t"));

        var outcome = await MergeAsync(Admin(), target.RtId.ToString(), sourceUserName,
            TestContext.Current.CancellationToken);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodValidationFailed);
    }

    [Fact]
    public async Task Method_UnknownTarget_IsTargetNotFound_AndTheSourceStays()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("notarget");

        var outcome = await MergeAsync(Admin(), "507f1f77bcf86cd799439011", fixture.Source.UserName, ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodTargetNotFound);
        await AssertUnchangedAsync(fixture);
    }

    [Theory]
    [InlineData("AdminPanelManagement", "octo_api")]
    [InlineData(UserManagement, "octo_api.read_only")]
    [InlineData(null, null)]
    public async Task Method_CallerWithoutRoleOrScope_IsForbidden_ForExistingAndMissingTarget_AndNothingChanges(
        string? role, string? scope)
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("caller");
        var principal = role == null
            ? null
            : new CkMethodPrincipal(Guid.NewGuid().ToString("N")[..24], [role], [scope!]);

        var existing = await MergeAsync(principal, fixture.Target.RtId.ToString(), fixture.Source.UserName, ct);
        var missing = await MergeAsync(principal, "507f1f77bcf86cd799439011", fixture.Source.UserName, ct);

        existing.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        existing.Failure.Parameters!["reason"].Should().Be("role-required");
        missing.Failure.Should().BeEquivalentTo(existing.Failure, "an unauthorized caller learns nothing about the target");
        await AssertUnchangedAsync(fixture);
    }

    [Fact]
    public async Task Method_SourceTheCallerCannotRead_IsSourceUserNotFound_AndNothingChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("noread");
        using var restricted = WithEvaluator(_ => RtDataPermissionDecision.NotVisible);

        var outcome = await MergeAsync(Admin(), fixture.Target.RtId.ToString(), fixture.Source.UserName, ct, restricted);

        outcome.Failure!.Code.Should().Be(UserMergeHandler.SourceUserNotFound);
        await AssertUnchangedAsync(fixture);
    }

    [Fact]
    public async Task Method_SourceTheCallerMayReadButNotWrite_IsForbidden_DataPermission_AndNothingChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("nowrite");
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        using var restricted = WithEvaluator(action => action == RtDataAction.Write
            ? RtDataPermissionDecision.NotPermitted
            : RtDataPermissionDecision.Allowed, evaluator);
        var caller = Guid.NewGuid().ToString("N")[..24];

        var outcome = await MergeAsync(new CkMethodPrincipal(caller, AdminRoles, ["octo_api"]),
            fixture.Target.RtId.ToString(), fixture.Source.UserName, ct, restricted);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        outcome.Failure.Parameters!["reason"].Should().Be("data-permission");
        await AssertUnchangedAsync(fixture);
        await evaluator.Received().EvaluateAsync(Arg.Any<Meshmakers.Octo.Runtime.Contracts.Repositories.IRuntimeRepository>(),
            Arg.Is<RtSecurityContext>(c => c.SubjectId == caller && c.Roles.Contains(UserManagement)),
            Arg.Is<RtEntityId>(e => e.RtId == fixture.Source.RtId), RtDataAction.Write, Arg.Any<bool>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Method_MergingAwayTheLastUserAdministrator_IsForbidden_LastAdministrator_LikeRest()
    {
        var ct = TestContext.Current.CancellationToken;
        await ClearAdministratorsAsync();
        var fixture = await NewFixtureAsync("lastadmin");
        await AddDirectRoleAsync(fixture.Source, UserManagement);

        var outcome = await MergeAsync(Admin(), fixture.Target.RtId.ToString(), fixture.Source.UserName, ct);
        var response = await RestClient(Guid.NewGuid().ToString("N"), AdminRoles).PostAsJsonAsync(
            TenantApiUrl($"users/{fixture.Target.UserName}/merge"), new { sourceUserName = fixture.Source.UserName }, ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        outcome.Failure.Parameters!["reason"].Should().Be("last-administrator");
        response.StatusCode.Should().Be(HttpStatusCode.Conflict);
        await AssertUnchangedAsync(fixture);
        SingleAudit(fixture.Target.RtId.ToString()).Details["reason"].Should().Be("last-administrator");
    }

    [Fact]
    public async Task Method_FailureOfTheMerge_IsMergeFailed_WithStepAndErrorCodes()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("failed");
        var merge = Substitute.For<IUserMergeService>();
        merge.MergeAsync(Arg.Any<RtUser>(), Arg.Any<RtUser>(), Arg.Any<Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange.RoleChangeCaller>(),
                Arg.Any<AuditActor>(), Arg.Any<CancellationToken>())
            .Returns(new UserMergeResult(UserMergeStatus.LoginAddFailed, null, "Google",
                [new IdentityError { Code = "LoginAlreadyAssociated", Description = "x" }], 1, 0));
        using var failing = _host.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<IUserMergeService>();
            s.AddSingleton(merge);
        }));

        var outcome = await MergeAsync(Admin(), fixture.Target.RtId.ToString(), fixture.Source.UserName, ct, failing);

        outcome.Failure!.Code.Should().Be(UserMergeHandler.MergeFailed);
        outcome.Failure.Parameters!["step"].Should().Be("addLogin");
        outcome.Failure.Parameters["loginProvider"].Should().Be("Google");
        outcome.Failure.Details!.Select(d => d.Code).Should().BeEquivalentTo("LoginAlreadyAssociated");
        SingleAudit(fixture.Target.RtId.ToString()).Details["transferredLogins"].Should().Be("1");
    }

    [Fact]
    public async Task Method_AForgedCallerWithoutAValidToken_IsRejectedByTheHost_AndNothingChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var fixture = await NewFixtureAsync("forged");
        var invoker = _host.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        foreach (var token in new string?[] { null, "", "not-a-jwt" })
        {
            var response = await invoker.InvokeAsync(Request(fixture.Target.RtId.ToString(), token,
                fixture.Source.UserName), ct);
            response.Success.Should().BeFalse();
            response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
        }

        await AssertUnchangedAsync(fixture);
        _events.Should().BeEmpty("the handler was never called");
    }

    #region Fixture

    /// <summary>
    ///     A target with its own login, one role and one refresh token; a source with two logins (Google, Microsoft), a custom
    ///     direct role, membership of a group and one refresh token. Provider keys carry the fixture's suffix, so two fixtures
    ///     can live side by side; the snapshot strips the suffix.
    /// </summary>
    private async Task<Fixture> NewFixtureAsync(string kind)
    {
        var suffix = $"{kind}-{Guid.NewGuid():N}";
        var target = await CreateTestUserAsync(NewName("target"));
        var source = await CreateTestUserAsync(NewName("source"));
        var targetRole = await NewRoleAsync();
        var sourceRole = await NewRoleAsync();
        await AddDirectRoleAsync(target, targetRole);
        await AddDirectRoleAsync(source, sourceRole);

        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var storedTarget = (await userManager.FindByIdAsync(target.RtId.ToString()))!;
            (await userManager.AddLoginAsync(storedTarget, new UserLoginInfo("Facebook", $"own|{suffix}", "Facebook")))
                .Succeeded.Should().BeTrue();
            var storedSource = (await userManager.FindByIdAsync(source.RtId.ToString()))!;
            (await userManager.AddLoginAsync(storedSource, new UserLoginInfo("Google", $"a|{suffix}", "Google")))
                .Succeeded.Should().BeTrue();
            (await userManager.AddLoginAsync(storedSource, new UserLoginInfo("Microsoft", $"b|{suffix}", "Microsoft")))
                .Succeeded.Should().BeTrue();
        }

        var group = await NewGroupAsync();
        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberUserAsync(group, source.RtId.ToString());
        }

        var sourceToken = await CreateOAuthTokenAsync(source.RtId.ToString(), "m7778-spa");
        await CreateOAuthTokenAsync(target.RtId.ToString(), "m7778-spa");
        return new Fixture(target, source, targetRole, sourceRole, group, suffix, sourceToken.RtId.ToString());
    }

    private async Task<State> SnapshotAsync(Fixture fixture)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var userStore = (OctoUserStore)scope.ServiceProvider.GetRequiredService<IUserStore<RtUser>>();
        var target = (await userManager.FindByIdAsync(fixture.Target.RtId.ToString()))!;
        var logins = await userManager.GetLoginsAsync(target);
        var resolve = true;
        foreach (var login in logins)
        {
            resolve &= (await userManager.FindByLoginAsync(login.LoginProvider, login.ProviderKey))?.RtId == target.RtId;
        }

        var members = await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberUserIdsAsync(fixture.Group);
        return new State(
            await userManager.FindByIdAsync(fixture.Source.RtId.ToString()) != null,
            logins.Select(l => $"{l.LoginProvider}:{l.ProviderKey.Split('|')[0]}").Order().ToList(),
            resolve,
            (await userStore.GetDirectRolesAsync(target)).Select(r => string.Equals(r, fixture.TargetRole, StringComparison.OrdinalIgnoreCase) ? "TARGETROLE" : r)
            .Order().ToList(),
            members.Contains(target.RtId.ToString()),
            members.Count,
            await GetValidOAuthTokenCountForSubjectAsync(fixture.Source.RtId.ToString()),
            await GetValidOAuthTokenCountForSubjectAsync(target.RtId.ToString()));
    }

    /// <summary>A refused merge leaves both users, the logins of the source and its refresh token as they were.</summary>
    private async Task AssertUnchangedAsync(Fixture fixture)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var source = await userManager.FindByIdAsync(fixture.Source.RtId.ToString());
        source.Should().NotBeNull("the source user still exists");
        (await userManager.GetLoginsAsync(source!)).Select(l => l.LoginProvider)
            .Should().BeEquivalentTo("Google", "Microsoft");
        var target = (await userManager.FindByIdAsync(fixture.Target.RtId.ToString()))!;
        (await userManager.GetLoginsAsync(target)).Select(l => l.LoginProvider).Should().BeEquivalentTo("Facebook");
        (await GetValidOAuthTokenCountForSubjectAsync(fixture.Source.RtId.ToString())).Should().Be(1);
    }

    private sealed record Fixture(RtUser Target, RtUser Source, string TargetRole, string SourceRole, OctoObjectId Group,
        string Suffix, string SourceTokenId);

    /// <summary>The comparable end state of a merge (role names of the fixture replaced by placeholders).</summary>
    private sealed record State(
        bool SourceExists,
        List<string> TargetLogins,
        bool LoginsResolveToTarget,
        List<string> TargetDirectRoles,
        bool TargetInSourceGroup,
        int SourceGroupMemberCount,
        int ValidSourceTokens,
        int ValidTargetTokens);

    #endregion

    #region Helpers

    private static string NewName(string prefix) => $"m7778_{prefix}_{Guid.NewGuid():N}";

    private static CkMethodPrincipal Admin(RtUser? user = null) =>
        new(user?.RtId.ToString() ?? "507f1f77bcf86cd799439012", AdminRoles, ["octo_api"]);

    private HttpClient RestClient(string subject, IEnumerable<string> roles)
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, subject);
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        foreach (var role in roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        return client;
    }

    private WebApplicationFactory<Program> WithEvaluator(Func<RtDataAction, RtDataPermissionDecision> decide,
        IRtDataPermissionEvaluator? evaluator = null)
    {
        evaluator ??= Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<Meshmakers.Octo.Runtime.Contracts.Repositories.IRuntimeRepository>(),
                Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(), Arg.Any<RtDataAction>(), Arg.Any<bool>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var decision = decide(call.ArgAt<RtDataAction>(3));
                return new RtDataPermissionVerdict(decision,
                    decision == RtDataPermissionDecision.Allowed ? RtDataPermissionReason.Open : RtDataPermissionReason.NoGrant);
            });
        return _host.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton(evaluator)));
    }

    private async Task<string> NewRoleAsync()
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var name = NewName("role");
        (await roleManager.CreateAsync(new RtRoleBuilder().WithName(name).Build())).Succeeded.Should().BeTrue();
        return name;
    }

    private async Task AddDirectRoleAsync(RtUser user, string role)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        if (role == UserManagement)
        {
            await EnsureUserManagementAsync();
        }

        var stored = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
        (await userManager.AddToRoleAsync(stored, role.ToUpperInvariant())).Succeeded.Should().BeTrue();
    }

    private async Task<OctoObjectId> NewGroupAsync()
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        var name = NewName("g");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        };
        await store.StoreAsync(group);
        return group.RtId;
    }

    private async Task<RtRole> EnsureUserManagementAsync()
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var role = await roleManager.FindByNameAsync(UserManagement);
        if (role == null)
        {
            role = new RtRoleBuilder().WithName(UserManagement).Build();
            role.RtWellKnownName = UserManagement;
            (await roleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
        }

        return role;
    }

    /// <summary>Removes every effective holder of UserManagement (direct, groups, mappings), as the guard tests do.</summary>
    private async Task ClearAdministratorsAsync()
    {
        var role = await EnsureUserManagementAsync();
        var roleId = role.RtId.ToString();
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        foreach (var holder in await userManager.GetUsersInRoleAsync(role.NormalizedName!))
        {
            await userManager.RemoveFromRoleAsync(holder, role.NormalizedName!);
        }

        var groups = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        foreach (var group in await groups.GetAllAsync())
        {
            var roles = await groups.GetRoleIdsAsync(group.RtId);
            if (roles.Contains(roleId))
            {
                await groups.SetRoleIdsAsync(group.RtId, roles.Where(r => r != roleId).ToList());
            }
        }

        var mappings = scope.ServiceProvider.GetRequiredService<IExternalTenantUserMappingStore>();
        foreach (var mapping in await mappings.GetAllAsync())
        {
            if (mapping.MappedRoleIds?.Contains(roleId) == true)
            {
                mapping.MappedRoleIds = new AttributeStringValueList(mapping.MappedRoleIds.Where(r => r != roleId).ToList());
                await mappings.StoreAsync(mapping);
            }
        }
    }

    private CapturedEvent SingleAudit(string target) =>
        _events.Single(e => e.Category == IdentityMethodAuditWriter.Category &&
                            e.Details.GetValueOrDefault("targetRtId") == target);

    private async Task<CkMethodOutcome> MergeAsync(CkMethodPrincipal? principal, string target, string? sourceUserName,
        CancellationToken ct, WebApplicationFactory<Program>? factory = null)
    {
        using var scope = (factory ?? _host).Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<UserMergeHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<UserMergeParameters>(Request(target, null, sourceUserName),
            new UserMergeParameters { SourceUserName = sourceUserName! })
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, ct);
    }

    private CkMethodRequest Request(string target, string? token, string? sourceUserName) => new(NormalizedSystemTenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = SystemIdentityCkIds.UserMergeMethodId,
        CkTypeId = "System.Identity/User",
        TargetRtId = target,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
        CallerAccessToken = token,
        ParametersJson = JsonSerializer.Serialize(new { sourceUserName })
    };

    private sealed record CapturedEvent(string Message, string? Category, Dictionary<string, string> Details);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner.Messages.Enqueue(formatter(state, exception) + (exception == null ? "" : " " + exception));
        }
    }

    #endregion
}
