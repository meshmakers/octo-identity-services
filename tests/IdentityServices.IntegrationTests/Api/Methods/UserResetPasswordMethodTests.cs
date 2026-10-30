using System.Collections.Concurrent;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
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
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7774: <c>User.ResetPassword</c> served by the identity service. Real MongoDB, the real identity host with
///     <c>Methods:Identity:EnablePasswordMethods=true</c>; the handler runs in a fresh DI scope without an HTTP request, as on
///     the bus, with the principal the host validated. The event repository and the logger are captured to check the audit
///     record and that no password value is written anywhere.
/// </summary>
public class UserResetPasswordMethodTests : IntegrationTestBase
{
    private const string OldPassword = "Test123!";
    private const string NewPassword = "Canary!Str0ng-7774";
    private static readonly string[] AdminRoles = ["UserManagement"];

    private readonly WebApplicationFactory<Program> _enabled;
    private readonly WebApplicationFactory<Program> _revocationFails;
    private readonly ConcurrentQueue<CapturedEvent> _events = new();
    private readonly CapturingLoggerProvider _logs = new();

    public UserResetPasswordMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _enabled = factory.WithWebHostBuilder(b => Configure(b, revocationFails: false));
        _revocationFails = factory.WithWebHostBuilder(b => Configure(b, revocationFails: true));
    }

    private void Configure(Microsoft.AspNetCore.Hosting.IWebHostBuilder b, bool revocationFails)
    {
        // UseSetting reaches the host configuration before Program reads Methods:Identity.
        b.UseSetting("Methods:Identity:EnablePasswordMethods", "true");
        b.ConfigureTestServices(services =>
        {
            // The test host has no broker: drop the bus side of the method host. Registration, validation, invoker and
            // handler stay.
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
                    _events.Enqueue(new CapturedEvent(call.ArgAt<string>(0), call.ArgAt<string>(3),
                        call.ArgAt<string?>(4),
                        (call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                        .ToDictionary(p => p.Key, p => p.Value)));
                    return Task.CompletedTask;
                });
            services.RemoveAll<IEventRepository>();
            services.AddSingleton(events);

            if (revocationFails)
            {
                var failing = Substitute.For<IUserCredentialChangeService>();
                failing.OnPasswordChangedAsync(Arg.Any<RtUser>(), Arg.Any<PasswordChangePath>(), Arg.Any<string?>(),
                        Arg.Any<CancellationToken>())
                    .Returns(Task.FromException(new InvalidOperationException("revocation failed")));
                services.RemoveAll<IUserCredentialChangeService>();
                services.AddSingleton(failing);
            }
        });
    }

    [Fact]
    public void SwitchOff_TheHostRegistersNoHandler_SoTheGatewayAnswersHandlerNotAvailable()
    {
        // the default configuration of every environment: nothing is hosted, nothing is announced
        Factory.Services.GetService<ICkMethodHandlerInvoker>().Should().BeNull();
        using var scope = Factory.Services.CreateScope();
        scope.ServiceProvider.GetService<UserResetPasswordHandler>().Should().BeNull();
    }

    [Fact]
    public void SwitchOn_TheHostHostsTheHandler()
    {
        using var scope = _enabled.Services.CreateScope();
        scope.ServiceProvider.GetService<UserResetPasswordHandler>().Should().NotBeNull();
    }

    [Fact]
    public async Task LockedOutUser_IsResetByAnAdministrator_LockoutLifted_NewPasswordSignsIn_SessionsRevoked_Audited()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        var subject = user.RtId.ToString();
        await LockOutAsync(userName);
        await CreateOAuthTokenAsync(subject, "m-spa");
        await CreateOAuthTokenAsync(subject, "m-spa");
        var other = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        await CreateOAuthTokenAsync(other.RtId.ToString(), "m-spa");
        var admin = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        var stampBefore = (await FindAsync(userName)).SecurityStamp;
        (await FindAsync(userName)).LockoutEnd.Should().NotBeNull("the precondition: the user is locked out");
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().BeNull("locked out");

        var outcome = await ResetAsync(Admin(admin), subject, NewPassword, ct);

        outcome.IsSuccess.Should().BeTrue();
        var stored = await FindAsync(userName);
        stored.LockoutEnd.Should().BeNull();
        stored.AccessFailedCount.Should().Be(0);
        stored.SecurityStamp.Should().NotBe(stampBefore);
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().NotBeNull();
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().BeNull();
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(0, "old refresh tokens fail");
        (await GetValidOAuthTokenCountForSubjectAsync(other.RtId.ToString())).Should().Be(1, "another user is untouched");

        var audit = SingleAudit(subject);
        audit.Details["outcome"].Should().Be("SUCCESS");
        audit.Details["lockoutLifted"].Should().Be("true");
        audit.Details["callerSubject"].Should().Be(admin.RtId.ToString());
        audit.TenantId.Should().Be(NormalizedSystemTenantId);
        NoSecretInAuditOrLogs();
    }

    [Fact]
    public async Task UserWithFailedAttemptsButNoLockout_HasTheCounterReset_AuditSaysNotLifted()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        var subject = user.RtId.ToString();
        using (var scope = _enabled.Services.CreateScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var current = (await manager.FindByIdAsync(subject))!;
            await manager.AccessFailedAsync(current);
            await manager.AccessFailedAsync(current);
        }

        (await FindAsync(userName)).AccessFailedCount.Should().BeGreaterThan(0);

        var outcome = await ResetAsync(Admin(), subject, NewPassword, ct);

        outcome.IsSuccess.Should().BeTrue();
        (await FindAsync(userName)).AccessFailedCount.Should().Be(0);
        SingleAudit(subject).Details["lockoutLifted"].Should().Be("false");
    }

    [Fact]
    public async Task ServiceToken_WithTheRole_ResetsThePassword_ActorIsTheClient()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);

        var outcome = await ResetAsync(new CkMethodPrincipal(null, AdminRoles, ["octo_api"], "svc-client"),
            user.RtId.ToString(), NewPassword, ct);

        outcome.IsSuccess.Should().BeTrue();
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().NotBeNull();
        SingleAudit(user.RtId.ToString()).Details["callerSubject"].Should().Be("svc-client");
    }

    [Fact]
    public async Task CallerWithoutTheRole_IsForbidden_ForAnExistingAndAMissingTarget_Identically_AndChangesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var victimName = NewUserName();
        var victim = await CreateTestUserAsync(victimName, password: OldPassword);
        await LockOutAsync(victimName);
        var caller = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        var plain = new CkMethodPrincipal(caller.RtId.ToString(), ["AdminPanelManagement"], ["octo_api"]);

        var existing = await ResetAsync(plain, victim.RtId.ToString(), NewPassword, ct);
        var missing = await ResetAsync(plain, "507f1f77bcf86cd799439011", NewPassword, ct);

        existing.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        missing.Failure.Should().BeEquivalentTo(existing.Failure, "an unauthorized caller learns nothing about the target");
        (await FindAsync(victimName)).LockoutEnd.Should().NotBeNull("a refused call lifts nothing");
        (await LoginAndGetAuthenticatedClientAsync(victimName, NewPassword, ct)).Should().BeNull();
        _events.Where(e => e.Details["outcome"] == "METHOD_FORBIDDEN").Should().HaveCount(2, "one audit record per call");
        _events.Select(e => e.Details["lockoutLifted"]).Should().OnlyContain(v => v == "false");
    }

    [Fact]
    public async Task ASelfCaller_WithoutTheRole_CannotResetItsOwnPassword()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        var subject = user.RtId.ToString();

        var outcome = await ResetAsync(new CkMethodPrincipal(subject, [], ["octo_api"]), subject, NewPassword, ct);

        outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
    }

    [Fact]
    public async Task NoPrincipal_IsForbidden()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewUserName(), password: OldPassword);

        (await ResetAsync(null, user.RtId.ToString(), NewPassword, ct)).Failure!.Code.Should().Be("METHOD_FORBIDDEN");
    }

    [Fact]
    public async Task UnknownTarget_IsTargetNotFound_ForAnAuthorizedCaller()
    {
        var ct = TestContext.Current.CancellationToken;

        var outcome = await ResetAsync(Admin(), "507f1f77bcf86cd799439011", NewPassword, ct);

        outcome.Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        SingleAudit("507f1f77bcf86cd799439011").Details["outcome"].Should().Be("METHOD_TARGET_NOT_FOUND");
    }

    [Fact]
    public async Task PolicyViolation_NamesTheFailedRules_NeverTheValue_ChangesAndLiftsNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        var subject = user.RtId.ToString();
        await LockOutAsync(userName);
        await CreateOAuthTokenAsync(subject, "m-spa");
        const string weak = "wk-ab";

        var outcome = await ResetAsync(Admin(), subject, weak, ct);

        outcome.Failure!.Code.Should().Be("PASSWORD_POLICY_VIOLATION");
        outcome.Failure.Details!.Select(d => d.Code).Should().Contain("PasswordTooShort");
        JsonSerializer.Serialize(outcome.Failure).Should().NotContain(weak);
        (await FindAsync(userName)).LockoutEnd.Should().NotBeNull("a failed call does not lift the lockout");
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(1, "a failed call revokes nothing");
        var audit = SingleAudit(subject);
        audit.Details["outcome"].Should().Be("PASSWORD_POLICY_VIOLATION");
        audit.Details["lockoutLifted"].Should().Be("false");
        _events.SelectMany(e => e.Details.Values).Append(string.Join(' ', _events.Select(e => e.Message)))
            .Should().NotContain(v => v.Contains(weak));
        _logs.Messages.Should().NotContain(m => m.Contains(weak));
    }

    [Fact]
    public async Task ShadowUser_HasNoLocalPassword()
    {
        var ct = TestContext.Current.CancellationToken;
        using var scope = _enabled.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var shadow = new Shared.TestUtilities.Builders.RtUserBuilder().WithUserName($"xt_a_{NewUserName()}")
            .WithEmail("shadow@example.com").Build();
        (await userManager.CreateAsync(shadow)).Succeeded.Should().BeTrue();

        (await ResetAsync(Admin(), shadow.RtId.ToString(), NewPassword, ct)).Failure!.Code
            .Should().Be("SHADOW_USER_PASSWORD_NOT_ALLOWED");
    }

    [Fact]
    public async Task WhenTheRevocationFails_TheCallThrows_NoSuccess_AndTheAuditStillRecordsTheFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        var subject = user.RtId.ToString();

        var act = () => ResetAsync(Admin(), subject, NewPassword, ct, _revocationFails);

        await act.Should().ThrowAsync<InvalidOperationException>();
        SingleAudit(subject).Details["outcome"].Should().Be("METHOD_HANDLER_FAILED");
    }

    [Fact]
    public async Task AForgedCaller_WithoutAValidToken_IsRejectedByTheHost_AndTheHandlerIsNotCalled()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        await LockOutAsync(userName);
        var subject = user.RtId.ToString();
        var invoker = _enabled.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        foreach (var token in new string?[] { null, "" })
        {
            var response = await invoker.InvokeAsync(Request(subject, token), ct);
            response.Success.Should().BeFalse();
            response.Error!.Code.Should().Be("METHOD_FORBIDDEN");
        }

        // The authority is not reachable in this test host, so a token cannot be validated and the host fails closed.
        foreach (var token in new[] { "not-a-jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4Iiwicm9sZSI6IlVzZXJNYW5hZ2VtZW50In0." })
        {
            var response = await invoker.InvokeAsync(Request(subject, token), ct);
            response.Success.Should().BeFalse();
            response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
        }

        var forged = Request(subject, "not-a-jwt") with
        {
            Caller = new CkMethodCaller { SubjectId = subject, Roles = ["UserManagement"] }
        };
        (await invoker.InvokeAsync(forged, ct)).Success.Should().BeFalse();
        (await FindAsync(userName)).LockoutEnd.Should().NotBeNull("nothing changed");
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().BeNull();
        _events.Should().BeEmpty("the handler was never called");
    }

    #region Helpers

    private static string NewUserName() => $"m7774_{Guid.NewGuid():N}";

    private static CkMethodPrincipal Admin(RtUser? user = null) =>
        new(user?.RtId.ToString() ?? "507f1f77bcf86cd799439012", AdminRoles, ["octo_api"]);

    private async Task<RtUser> FindAsync(string userName)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName))!;
    }

    /// <summary>Locks the user out the way wrong sign-ins do: through the failed-access counter of the manager.</summary>
    private async Task LockOutAsync(string userName)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var user = (await manager.FindByNameAsync(userName))!;
        for (var i = 0; i < 5; i++)
        {
            await manager.AccessFailedAsync(user);
        }
    }

    private CapturedEvent SingleAudit(string target) =>
        _events.Single(e => e.Category == IdentityMethodAuditWriter.Category && e.Details.GetValueOrDefault("targetRtId") == target);

    private void NoSecretInAuditOrLogs()
    {
        _events.SelectMany(e => e.Details.Values).Concat(_events.Select(e => e.Message)).Should()
            .NotContain(v => v.Contains(NewPassword) || v.Contains(OldPassword));
        _logs.Messages.Should().NotContain(m => m.Contains(NewPassword) || m.Contains(OldPassword));
    }

    private async Task<CkMethodOutcome> ResetAsync(CkMethodPrincipal? principal, string target, string next,
        CancellationToken ct, WebApplicationFactory<Program>? factory = null)
    {
        using var scope = (factory ?? _enabled).Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<UserResetPasswordHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<UserResetPasswordParameters>(Request(target, null),
            new UserResetPasswordParameters { NewPassword = next })
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, ct);
    }

    private CkMethodRequest Request(string target, string? token) => new(NormalizedSystemTenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = SystemIdentityCkIds.UserResetPasswordMethodId,
        CkTypeId = "System.Identity/User",
        TargetRtId = target,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
        CallerAccessToken = token,
        ParametersJson = JsonSerializer.Serialize(new { newPassword = NewPassword })
    };

    private sealed record CapturedEvent(string TenantId, string Message, string? Category,
        Dictionary<string, string> Details);

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
                Func<TState, Exception?, string> formatter)
                => owner.Messages.Enqueue(formatter(state, exception) + exception);
        }
    }

    #endregion
}
