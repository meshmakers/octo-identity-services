using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
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
using OtpNet;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7879: <c>User.DisableTwoFactor-1</c> and its REST facade <c>POST {tenant}/v1/users/{userName}/disableTwoFactor</c>. Real
///     MongoDB and the real identity host (the bus side of the method host is removed, the test host has no broker); the handler
///     runs in a fresh scope without an HTTP request, as on the bus, with the principal the host validated. The event repository
///     and the logger are captured to check the audit and that no authenticator key or recovery code is written anywhere.
/// </summary>
public class UserDisableTwoFactorMethodTests : IntegrationTestBase
{
    private const string Password = "Test123!";
    private static readonly string[] AdminRoles = ["UserManagement"];

    private readonly WebApplicationFactory<Program> _host;
    private readonly WebApplicationFactory<Program> _revocationFails;
    private readonly ConcurrentQueue<CapturedEvent> _events = new();
    private readonly CapturingLoggerProvider _logs = new();

    public UserDisableTwoFactorMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _host = factory.WithWebHostBuilder(b => Configure(b, revocationFails: false));
        _revocationFails = factory.WithWebHostBuilder(b => Configure(b, revocationFails: true));
    }

    private void Configure(Microsoft.AspNetCore.Hosting.IWebHostBuilder b, bool revocationFails)
    {
        b.ConfigureTestServices(services =>
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

            if (revocationFails)
            {
                var failing = Substitute.For<IUserCredentialChangeService>();
                failing.OnSecondFactorDisabledAsync(Arg.Any<RtUser>(), Arg.Any<TwoFactorDisablePath>(),
                        Arg.Any<string?>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
                    .Returns(Task.FromException(new InvalidOperationException("revocation failed")));
                services.RemoveAll<IUserCredentialChangeService>();
                services.AddSingleton(failing);
            }
        });
    }

    [Fact]
    public void TheHandler_IsHostedWithoutThePasswordSwitch_BecauseItCarriesNoSecret()
    {
        using var scope = Factory.Services.CreateScope();
        scope.ServiceProvider.GetService<UserDisableTwoFactorHandler>().Should().NotBeNull(
            "the method has no sensitive parameter or result, so EnablePasswordMethods does not gate it");
    }

    [Fact]
    public async Task Method_SwitchesTheSecondFactorOff_UserSignsInWithThePassword_AndEnrolsAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: Password);
        var subject = user.RtId.ToString();
        var (oldKey, oldCodes) = await EnrolAsync(userName);
        await CreateOAuthTokenAsync(subject, "m-spa");
        var other = await CreateTestUserAsync(NewUserName(), password: Password);
        await CreateOAuthTokenAsync(other.RtId.ToString(), "m-spa");
        var admin = await CreateTestUserAsync(NewUserName(), password: Password);
        var stampBefore = (await FindAsync(userName)).SecurityStamp;
        (await LoginAsync(userName, ct))!.RequiresTwoFactor.Should().BeTrue("the precondition: the second factor is on");

        var outcome = await DisableAsync(Admin(admin), subject, ct);

        outcome.IsSuccess.Should().BeTrue();
        await AssertSwitchedOffAsync(userName, stampBefore);
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(0, "old refresh tokens fail");
        (await GetValidOAuthTokenCountForSubjectAsync(other.RtId.ToString())).Should().Be(1, "another user is untouched");
        var login = await LoginAsync(userName, ct);
        login!.Success.Should().BeTrue("the user signs in with the password alone");
        login.RequiresTwoFactor.Should().BeFalse();
        await EnrolAgainOverHttpAsync(userName, ct);

        var audit = SingleAudit(subject);
        audit.Details["outcome"].Should().Be("SUCCESS");
        audit.Details[UserDisableTwoFactorHandler.TwoFactorWasEnabledDetail].Should().Be("true");
        audit.Details["callerSubject"].Should().Be(admin.RtId.ToString());
        NoAuthenticatorMaterialInAuditOrLogs(oldKey, oldCodes);
        _logs.Messages.Should().Contain(m => m.Contains("Second factor switched off by an administrator") &&
                                             m.Contains(subject) && m.Contains(admin.UserName!));
    }

    [Fact]
    public async Task Method_OnAUserWithoutSecondFactor_IsIdempotent_AuditSaysItWasOff()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewUserName(), password: Password);

        var outcome = await DisableAsync(Admin(), user.RtId.ToString(), ct);

        outcome.IsSuccess.Should().BeTrue();
        SingleAudit(user.RtId.ToString()).Details[UserDisableTwoFactorHandler.TwoFactorWasEnabledDetail]
            .Should().Be("false");
    }

    [Fact]
    public async Task Method_ServiceTokenWithTheRole_SwitchesItOff()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: Password);
        await EnrolAsync(userName);

        var outcome = await DisableAsync(new CkMethodPrincipal(null, AdminRoles, ["octo_api"], "svc-client"),
            user.RtId.ToString(), ct);

        outcome.IsSuccess.Should().BeTrue();
        (await FindAsync(userName)).TwoFactorEnabled.Should().BeFalse();
        SingleAudit(user.RtId.ToString()).Details["callerSubject"].Should().Be("svc-client");
    }

    [Theory]
    [InlineData("AdminPanelManagement", "octo_api")]
    [InlineData("UserManagement", "octo_api.read_only")]
    [InlineData(null, null)]
    public async Task Method_CallerWithoutRoleOrScope_IsForbidden_ForExistingAndMissingTarget_AndChangesNothing(
        string? role, string? scope)
    {
        var ct = TestContext.Current.CancellationToken;
        var victimName = NewUserName();
        var victim = await CreateTestUserAsync(victimName, password: Password);
        await EnrolAsync(victimName);
        var principal = role == null
            ? null
            : new CkMethodPrincipal(Guid.NewGuid().ToString("N")[..24], [role], [scope!]);

        var existing = await DisableAsync(principal, victim.RtId.ToString(), ct);
        var missing = await DisableAsync(principal, "507f1f77bcf86cd799439011", ct);

        existing.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        missing.Failure.Should().BeEquivalentTo(existing.Failure, "an unauthorized caller learns nothing about the target");
        (await FindAsync(victimName)).TwoFactorEnabled.Should().BeTrue("a refused call changes nothing");
    }

    [Fact]
    public async Task Method_UnknownTarget_IsTargetNotFound_ForAnAuthorizedCaller()
    {
        var ct = TestContext.Current.CancellationToken;

        var outcome = await DisableAsync(Admin(), "507f1f77bcf86cd799439011", ct);

        outcome.Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        SingleAudit("507f1f77bcf86cd799439011").Details["outcome"].Should().Be("METHOD_TARGET_NOT_FOUND");
    }

    [Fact]
    public async Task Method_WhenTheRevocationFails_TheCallThrows_AndTheAuditRecordsTheFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: Password);
        await EnrolAsync(userName);

        var act = () => DisableAsync(Admin(), user.RtId.ToString(), ct, _revocationFails);

        await act.Should().ThrowAsync<InvalidOperationException>();
        SingleAudit(user.RtId.ToString()).Details["outcome"].Should().Be("METHOD_HANDLER_FAILED");
    }

    [Fact]
    public async Task Method_AForgedCallerWithoutAValidToken_IsRejectedByTheHost_AndNothingChanges()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: Password);
        await EnrolAsync(userName);
        var invoker = _host.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        foreach (var token in new string?[] { null, "", "not-a-jwt" })
        {
            var response = await invoker.InvokeAsync(Request(user.RtId.ToString(), token), ct);
            response.Success.Should().BeFalse();
            response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
        }

        (await FindAsync(userName)).TwoFactorEnabled.Should().BeTrue("nothing changed");
        _events.Should().BeEmpty("the handler was never called");
    }

    [Fact]
    public async Task Rest_SwitchesTheSecondFactorOff_LikeTheMethod()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: Password);
        await EnrolAsync(userName);
        await CreateOAuthTokenAsync(user.RtId.ToString(), "m-spa");
        var stampBefore = (await FindAsync(userName)).SecurityStamp;

        var response = await HostClient().SendAsync(RestRequest(userName), ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        (await response.Content.ReadFromJsonAsync<UserTwoFactorDisableResultDto>(ct))!.TwoFactorWasEnabled
            .Should().BeTrue();
        await AssertSwitchedOffAsync(userName, stampBefore);
        (await GetValidOAuthTokenCountForSubjectAsync(user.RtId.ToString())).Should().Be(0);
        (await LoginAsync(userName, ct))!.Success.Should().BeTrue();
        _logs.Messages.Should().Contain(m => m.Contains("Second factor switched off by an administrator") &&
                                             m.Contains("AdminRest"));
    }

    [Fact]
    public async Task Rest_UnknownUser_Is404()
    {
        var response = await HostClient().SendAsync(RestRequest($"nobody_{Guid.NewGuid():N}"),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Rest_WithoutUserManagementRole_Is403_AndChangesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: Password);
        await EnrolAsync(userName);
        var request = RestRequest(userName);
        request.Headers.Add(TestAuthHandler.RoleHeader, "AssetViewer");

        var response = await HostClient().SendAsync(request, ct);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await FindAsync(userName)).TwoFactorEnabled.Should().BeTrue();
    }

    #region Helpers

    private static string NewUserName() => $"m7879_{Guid.NewGuid():N}";

    private static CkMethodPrincipal Admin(RtUser? user = null) =>
        new(user?.RtId.ToString() ?? "507f1f77bcf86cd799439012", AdminRoles, ["octo_api"]);

    /// <summary>A client of the capturing host with the same test bearer as <see cref="IntegrationTestBase.Client" />.</summary>
    private HttpClient HostClient()
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = Client.DefaultRequestHeaders.Authorization;
        return client;
    }

    private HttpRequestMessage RestRequest(string userName) =>
        new(HttpMethod.Post, TenantApiUrl($"users/{Uri.EscapeDataString(userName)}/disableTwoFactor"))
        {
            Content = JsonContent.Create(new { })
        };

    private async Task<RtUser> FindAsync(string userName)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName))!;
    }

    /// <summary>Enrols an authenticator the way the self-service does (key, recovery codes, flag) and returns the material.</summary>
    private async Task<(string Key, IReadOnlyList<string> Codes)> EnrolAsync(string userName)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var user = (await manager.FindByNameAsync(userName))!;
        (await manager.ResetAuthenticatorKeyAsync(user)).Succeeded.Should().BeTrue();
        var codes = (await manager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10))!.ToList();
        (await manager.SetTwoFactorEnabledAsync(user, true)).Succeeded.Should().BeTrue();
        var key = (await manager.GetAuthenticatorKeyAsync(user))!;
        return (key, codes);
    }

    private async Task AssertSwitchedOffAsync(string userName, string? stampBefore)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var stored = (await manager.FindByNameAsync(userName))!;
        stored.TwoFactorEnabled.Should().BeFalse();
        (await manager.GetAuthenticatorKeyAsync(stored)).Should().BeNull("the authenticator key is removed");
        (await manager.CountRecoveryCodesAsync(stored)).Should().Be(0, "the recovery codes are removed");
        stored.SecurityStamp.Should().NotBe(stampBefore, "the security stamp is rotated");
    }

    private async Task EnrolAgainOverHttpAsync(string userName, CancellationToken ct)
    {
        var client = await LoginAndGetAuthenticatedClientAsync(userName, Password, ct);
        client.Should().NotBeNull();
        var setup = await (await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct))
            .Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        var totp = new Totp(Base32Encoding.ToBytes(setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant()));
        var verify = await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"),
            new { Code = totp.ComputeTotp() }, ct);
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        (await FindAsync(userName)).TwoFactorEnabled.Should().BeTrue("the user enrolled a new authenticator");
    }

    private async Task<LoginResultDto?> LoginAsync(string userName, CancellationToken ct)
    {
        var response = await CreateAnonymousClient().PostAsJsonAsync(AuthApiUrl("login"),
            new LoginRequestDto { Username = userName, Password = Password }, ct);
        return await response.Content.ReadFromJsonAsync<LoginResultDto>(ct);
    }

    private CapturedEvent SingleAudit(string target) =>
        _events.Single(e => e.Category == IdentityMethodAuditWriter.Category &&
                            e.Details.GetValueOrDefault("targetRtId") == target);

    private void NoAuthenticatorMaterialInAuditOrLogs(string key, IReadOnlyList<string> codes)
    {
        var secrets = codes.Append(key).ToList();
        _events.SelectMany(e => e.Details.Values).Concat(_events.Select(e => e.Message)).Should()
            .NotContain(v => secrets.Any(v.Contains));
        _logs.Messages.Should().NotContain(m => secrets.Any(m.Contains));
    }

    private async Task<CkMethodOutcome> DisableAsync(CkMethodPrincipal? principal, string target, CancellationToken ct,
        WebApplicationFactory<Program>? factory = null)
    {
        using var scope = (factory ?? _host).Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<UserDisableTwoFactorHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<UserDisableTwoFactorParameters>(Request(target, null),
            new UserDisableTwoFactorParameters())
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, ct);
    }

    private CkMethodRequest Request(string target, string? token) => new(NormalizedSystemTenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = SystemIdentityCkIds.UserDisableTwoFactorMethodId,
        CkTypeId = "System.Identity/User",
        TargetRtId = target,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
        CallerAccessToken = token,
        ParametersJson = JsonSerializer.Serialize(new { })
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
