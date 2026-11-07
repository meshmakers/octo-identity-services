using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
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

namespace IdentityServices.IntegrationTests.Api.Manage;

/// <summary>
///     AB#8414: the account pages' <c>POST api/manage/change-password</c> and <c>set-password</c> are facades of
///     <c>User.ChangePassword-1</c> and the new <c>User.SetPassword-1</c>, also while
///     <c>Methods:Identity:EnablePasswordMethods</c> keeps the password methods off the bus (production gate 2026-10-23, until
///     B0). Real MongoDB, real identity host, real cookie sign-in. The event hub is a substitute that records every call: the
///     password must never reach it. Logs, audit events and activity tags are captured for the canary. The security stamp is
///     validated on every request in these hosts, so a session whose cookie still carries the old stamp ends at once.
///     The REST contract of the session revocation stays covered by <see cref="PasswordChangeRevokesSessionsTests" />.
/// </summary>
public class AccountPasswordMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string OldPassword = "Test123!";

    private readonly ConcurrentQueue<Dictionary<string, string>> _methodAudit = new();
    private readonly ConcurrentQueue<string> _auditMessages = new();
    private readonly CapturingLoggerProvider _logs = new();
    private readonly ConcurrentQueue<string> _activityTags = new();
    private readonly ActivityListener _activities;
    private readonly IEventRepository _events = Substitute.For<IEventRepository>();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public AccountPasswordMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _events.When(e => e.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(),
                Arg.Any<RtEventLevelsEnum>(), Arg.Any<string>(), Arg.Any<string?>(),
                Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                var details = (call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                    .ToDictionary(d => d.Key, d => d.Value);
                _auditMessages.Enqueue(call.ArgAt<string>(3) + " " + string.Join(";", details.Select(d => d.Key + "=" + d.Value)));
                if (call.ArgAt<string?>(4) == IdentityMethodAuditWriter.Category)
                {
                    _methodAudit.Enqueue(details);
                }
            });
        _activities = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                _activityTags.Enqueue(activity.DisplayName);
                foreach (var tag in activity.TagObjects)
                {
                    _activityTags.Enqueue($"{tag.Key}={tag.Value}");
                }
            }
        };
        ActivitySource.AddActivityListener(_activities);
    }

    public static TheoryData<string> PasswordMethodSwitch => new() { "false", "true" };

    /// <summary>Every derived host keeps configuration file watchers; dispose them (CI allows 128 inotify instances).</summary>
    public void Dispose()
    {
        _activities.Dispose();
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    #region ChangePassword

    [Theory]
    [MemberData(nameof(PasswordMethodSwitch))]
    public async Task AccountChangePassword_RunsTheMethod_NewWorks_OldFails_OtherSessionsEnd_ThisSessionStays(
        string enablePasswordMethods)
    {
        var host = Host(enablePasswordMethods);
        var ct = TestContext.Current.CancellationToken;
        var newPassword = Canary();
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        var subject = user.RtId.ToString();
        await CreateOAuthTokenAsync(subject, "m-spa");
        var stampBefore = (await FindAsync(user.UserName!))!.SecurityStamp;
        using var page = await SignInAsync(host, user.UserName!, OldPassword);
        using var otherBrowser = await SignInAsync(host, user.UserName!, OldPassword);

        var response = await page.PostAsJsonAsync(ManageApiUrl("change-password"), new ChangePasswordRequestDto
        {
            CurrentPassword = OldPassword, NewPassword = newPassword, ConfirmPassword = newPassword
        }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!.Success.Should().BeTrue();
        (await FindAsync(user.UserName!))!.SecurityStamp.Should().NotBe(stampBefore);
        (await LoginAsync(host, user.UserName!, newPassword)).Should().BeTrue("the new password works");
        (await LoginAsync(host, user.UserName!, OldPassword)).Should().BeFalse("the old password fails");
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(0, "old refresh tokens fail");
        (await page.GetAsync(ManageApiUrl("2fa/status"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK, "the page's own cookie was re-issued with the new security stamp");
        (await otherBrowser.GetAsync(ManageApiUrl("2fa/status"), ct)).StatusCode.Should()
            .NotBe(HttpStatusCode.OK, "another session still carries the old security stamp and ends");

        var record = MethodRecordsFor(subject).Should().ContainSingle().Subject;
        record["methodId"].Should().Be(SystemIdentityCkIds.UserChangePasswordMethodId);
        record["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        record["callerSubject"].Should().Be(subject);
        AssertNothingReachedTheBroker();
        AssertCanaryNowhere(newPassword);
    }

    [Fact]
    public async Task AccountChangePassword_WrongCurrentPassword_KeepsTheAnswer_AndCountsAFailedSignIn()
    {
        var host = Host("false");
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        using var page = await SignInAsync(host, user.UserName!, OldPassword);

        var response = await page.PostAsJsonAsync(ManageApiUrl("change-password"), new ChangePasswordRequestDto
        {
            CurrentPassword = "Wr0ng!Passw0rd", NewPassword = "N3w!Passw0rd-8414", ConfirmPassword = "N3w!Passw0rd-8414"
        }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!;
        body.Success.Should().BeFalse();
        body.ErrorMessage.Should().Be("Failed to change password");
        body.Errors.Should().ContainSingle().Which.Should().Be(EnglishAsTheRequest(() => Describer().PasswordMismatch().Description));
        (await FindAsync(user.UserName!))!.AccessFailedCount.Should()
            .Be(1, "the method counts a wrong current password like a failed sign-in (behaviour change, CHANGELOG)");
        MethodRecordsFor(user.RtId.ToString()).Should().ContainSingle().Which["outcome"].Should().Be("CURRENT_PASSWORD_INVALID");
    }

    [Fact]
    public async Task AccountChangePassword_PolicyViolation_KeepsTheRuleDescriptions()
    {
        var host = Host("false");
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        using var page = await SignInAsync(host, user.UserName!, OldPassword);

        var response = await page.PostAsJsonAsync(ManageApiUrl("change-password"), new ChangePasswordRequestDto
        {
            CurrentPassword = OldPassword, NewPassword = "wk", ConfirmPassword = "wk"
        }, ct);

        var body = (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!;
        body.Success.Should().BeFalse();
        var requiredLength = Options().Password.RequiredLength;
        var tooShort = EnglishAsTheRequest(() => Describer().PasswordTooShort(requiredLength).Description);
        body.Errors.Should().Contain(tooShort, "the description of each failed rule is rebuilt from its code");
        body.Errors.Should().NotContain("PasswordTooShort", "codes are not shown as text");
    }

    [Fact]
    public async Task AccountChangePassword_OfALockedOutUser_IsRefused_PasswordUnchanged()
    {
        var host = Host("false");
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        using var page = await SignInAsync(host, user.UserName!, OldPassword);
        await LockOutAsync(user.UserName!);
        var hashBefore = (await FindAsync(user.UserName!))!.PasswordHash;

        var response = await page.PostAsJsonAsync(ManageApiUrl("change-password"), new ChangePasswordRequestDto
        {
            CurrentPassword = OldPassword, NewPassword = "N3w!Passw0rd-8414", ConfirmPassword = "N3w!Passw0rd-8414"
        }, ct);

        var body = (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!;
        body.Success.Should().BeFalse();
        body.Errors.Should().ContainSingle().Which.Should().Be(ManageApiController.UserLockedOutMessage);
        (await FindAsync(user.UserName!))!.PasswordHash.Should().Be(hashBefore);
    }

    #endregion

    #region SetPassword

    [Theory]
    [MemberData(nameof(PasswordMethodSwitch))]
    public async Task AccountSetPassword_OfAUserWithoutPassword_RunsTheMethod_SessionStays_NothingOnTheBus(
        string enablePasswordMethods)
    {
        var host = Host(enablePasswordMethods);
        var ct = TestContext.Current.CancellationToken;
        var newPassword = Canary();
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        var subject = user.RtId.ToString();
        using var page = await SignInAsync(host, user.UserName!, OldPassword);
        await RemovePasswordAsync(user.UserName!); // a user with external logins only
        await CreateOAuthTokenAsync(subject, "m-spa");

        var response = await page.PostAsJsonAsync(ManageApiUrl("set-password"), new SetPasswordRequestDto
        {
            NewPassword = newPassword, ConfirmPassword = newPassword
        }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!.Success.Should().BeTrue();
        (await LoginAsync(host, user.UserName!, newPassword)).Should().BeTrue();
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(0, "old refresh tokens fail");
        (await page.GetAsync(ManageApiUrl("2fa/status"), ct)).StatusCode.Should().Be(HttpStatusCode.OK);

        var record = MethodRecordsFor(subject).Should().ContainSingle().Subject;
        record["methodId"].Should().Be(SystemIdentityCkIds.UserSetPasswordMethodId);
        record["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        AssertNothingReachedTheBroker();
        AssertCanaryNowhere(newPassword);
    }

    [Fact]
    public async Task AccountSetPassword_OfAUserWithAPassword_KeepsTheAnswer_AndCallsNoMethod()
    {
        var host = Host("false");
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        using var page = await SignInAsync(host, user.UserName!, OldPassword);

        var response = await page.PostAsJsonAsync(ManageApiUrl("set-password"), new SetPasswordRequestDto
        {
            NewPassword = "N3w!Passw0rd-8414", ConfirmPassword = "different"
        }, ct);

        var body = (await response.Content.ReadFromJsonAsync<PasswordResultDto>(ct))!;
        body.Success.Should().BeFalse();
        body.ErrorMessage.Should().Be("User already has a password. Use change-password instead.",
            "an existing password is reported before a confirmation mismatch, as before");
        (await LoginAsync(host, user.UserName!, OldPassword)).Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(PasswordMethodSwitch))]
    public async Task SetPasswordMethod_Self_WithAPassword_IsPasswordAlreadySet_Shadow_IsRefused_Other_IsForbidden(
        string enablePasswordMethods)
    {
        var host = Host(enablePasswordMethods);
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        var subject = user.RtId.ToString();

        (await SetViaMethodAsync(host, Self(subject), subject, "N3w!Passw0rd-8414")).Error!.Code.Should()
            .Be(UserSetPasswordHandler.PasswordAlreadySet);
        (await LoginAsync(host, user.UserName!, OldPassword)).Should().BeTrue("the existing password is never replaced");

        var shadow = await CreateShadowUserAsync();
        var shadowId = shadow.RtId.ToString();
        (await SetViaMethodAsync(host, Self(shadowId), shadowId, "N3w!Passw0rd-8414")).Error!.Code.Should()
            .Be(UserSetPasswordHandler.ShadowUserPasswordNotAllowed);
        (await FindAsync(shadow.UserName!))!.PasswordHash.Should().BeNull();

        var withoutPassword = await CreateTestUserAsync(NewName(), password: OldPassword);
        await RemovePasswordAsync(withoutPassword.UserName!);
        var targetId = withoutPassword.RtId.ToString();
        foreach (var other in new[]
                 {
                     Self(subject),
                     new CkMethodPrincipal(subject, ["UserManagement", "TenantManagement"], ["octo_api"])
                 })
        {
            (await SetViaMethodAsync(host, other, targetId, "N3w!Passw0rd-8414")).Error!.Code.Should()
                .Be(CkMethodErrorCodes.MethodForbidden, "self only; an administrator uses ResetPassword");
        }

        (await FindAsync(withoutPassword.UserName!))!.PasswordHash.Should().BeNull();
    }

    #endregion

    #region Token path and facade guard

    public static TheoryData<string, string[]> ScopesWithoutTheApiScope => new()
    {
        { "ChangePassword", [] },
        { "ChangePassword", ["octo_api.read_only"] },
        { "SetPassword", [] },
        { "SetPassword", ["octo_api.read_only"] }
    };

    [Theory]
    [MemberData(nameof(ScopesWithoutTheApiScope))]
    public async Task ATokenWithoutTheApiScope_CannotCallTheMethods_EvenForItsOwnUser(string method, string[] scopes)
    {
        // The GraphQL gateway reaches the methods through the dispatcher with the caller of the bearer token. The switch is
        // on here, so the methods are hosted for every caller; the scope alone decides.
        var host = Host("true");
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        var subject = user.RtId.ToString();
        if (method == "SetPassword")
        {
            await RemovePasswordAsync(user.UserName!);
        }

        var caller = new CkMethodPrincipal(subject, [], scopes);
        var response = method == "SetPassword"
            ? await SetViaMethodAsync(host, caller, subject, "N3w!Passw0rd-8414")
            : await DispatchAsync(host, caller, SystemIdentityCkIds.UserChangePasswordMethodId, subject,
                new UserChangePasswordParameters { CurrentPassword = OldPassword, NewPassword = "N3w!Passw0rd-8414" });

        response.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        var stored = (await FindAsync(user.UserName!))!;
        if (method == "SetPassword")
        {
            stored.PasswordHash.Should().BeNull();
        }
        else
        {
            (await LoginAsync(host, user.UserName!, OldPassword)).Should().BeTrue();
        }
    }

    [Fact]
    public async Task ATokenWithTheApiScope_CallsSetPasswordForItsOwnUser_WhenTheSwitchIsOn()
    {
        var host = Host("true");
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        var subject = user.RtId.ToString();
        await RemovePasswordAsync(user.UserName!);

        (await SetViaMethodAsync(host, Self(subject), subject, "N3w!Passw0rd-8414")).Success.Should().BeTrue();
        (await LoginAsync(host, user.UserName!, "N3w!Passw0rd-8414")).Should().BeTrue();
    }

    [Fact]
    public async Task ABearerToken_DoesNotReachTheAccountEndpoints()
    {
        // The account endpoints authenticate the session cookie only (default scheme of ASP.NET Identity); a bearer token,
        // even with octo_api and an administrator role, is not a signed-in account page.
        var host = Host("false");
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        await RemovePasswordAsync(user.UserName!);
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, user.RtId.ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.ScopeHeader, "octo_api");

        var response = await client.PostAsJsonAsync(ManageApiUrl("set-password"),
            new SetPasswordRequestDto { NewPassword = "N3w!Passw0rd-8414", ConfirmPassword = "N3w!Passw0rd-8414" }, ct);

        response.StatusCode.Should().NotBe(HttpStatusCode.OK);
        (await FindAsync(user.UserName!))!.PasswordHash.Should().BeNull();
        MethodRecordsFor(user.RtId.ToString()).Should().BeEmpty();
    }

    [Fact]
    public async Task TheAccountFacade_RefusesAPrincipalThatIsNotTheSessionCookieOfTheTarget()
    {
        var host = Host("false");
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        await RemovePasswordAsync(user.UserName!);
        var subject = user.RtId.ToString();
        var userIdClaim = Options().ClaimsIdentity.UserIdClaimType;

        var bearer = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(userIdClaim, subject), new Claim("sub", subject), new Claim("scope", "octo_api")], "Bearer"));
        var otherCookie = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(userIdClaim, OctoObjectId.GenerateNewId().ToString())], IdentityConstants.ApplicationScheme));
        var unauthenticated = new ClaimsPrincipal(new ClaimsIdentity([new Claim(userIdClaim, subject)]));

        foreach (var principal in new[] { bearer, otherCookie, unauthenticated })
        {
            using var scope = host.Services.CreateScope();
            var facade = scope.ServiceProvider.GetRequiredService<IIdentityMethodFacade>();
            var response = await facade.InvokeForAccountOwnerAsync(SystemIdentityCkIds.UserSetPasswordMethodId, subject,
                new UserSetPasswordParameters { NewPassword = "N3w!Passw0rd-8414" }, principal,
                TestContext.Current.CancellationToken);
            response.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        }

        (await FindAsync(user.UserName!))!.PasswordHash.Should().BeNull();
        MethodRecordsFor(subject).Should().BeEmpty("the facade refuses before any call");
    }

    [Fact]
    public void SwitchOff_ChangeAndSetPassword_RunInThisProcess_ButAreNotOfferedOnTheBus()
    {
        var host = Host("false");

        var transport = host.Services.GetRequiredService<ICkInProcessMethodTransport>();
        transport.CanHandle(SystemIdentityCkIds.UserChangePasswordMethodId).Should().BeTrue();
        transport.CanHandle(SystemIdentityCkIds.UserSetPasswordMethodId).Should().BeTrue();
        IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions()).Select(h => h.MethodId).Should()
            .NotContain([SystemIdentityCkIds.UserChangePasswordMethodId, SystemIdentityCkIds.UserSetPasswordMethodId]);
    }

    #endregion

    #region Helpers

    private WebApplicationFactory<Program> Host(string enablePasswordMethods)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Methods:Identity:EnablePasswordMethods", enablePasswordMethods);
            b.ConfigureTestServices(services =>
            {
                // The test host has no broker: drop the bus side of the method host (announcement, heartbeat).
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }

                // Validate the security stamp of the session cookie on every request: a stale cookie ends at once.
                services.PostConfigure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.Zero);
                services.AddSingleton(_events);
                services.RemoveAll<IDistributionEventHubService>();
                services.AddSingleton(_eventHub);
                services.RemoveAll<IUserEmailInteractionService>();
                services.AddSingleton(Substitute.For<IUserEmailInteractionService>());
                services.AddLogging(l => l.AddProvider(_logs));
            });
        });
        _hosts.Add(host);
        return host;
    }

    private static async Task<HttpClient> SignInAsync(WebApplicationFactory<Program> host, string userName, string password)
    {
        var client = host.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
        var response = await client.PostAsJsonAsync(AuthApiUrl("login"),
            new { Username = userName, Password = password, RememberLogin = true }, TestContext.Current.CancellationToken);
        (await response.Content.ReadFromJsonAsync<LoginResultDto>(TestContext.Current.CancellationToken))!.Success
            .Should().BeTrue();
        return client;
    }

    private static async Task<bool> LoginAsync(WebApplicationFactory<Program> host, string userName, string password)
    {
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
        var response = await client.PostAsJsonAsync(AuthApiUrl("login"),
            new { Username = userName, Password = password, RememberLogin = false }, TestContext.Current.CancellationToken);
        return response.IsSuccessStatusCode &&
               (await response.Content.ReadFromJsonAsync<LoginResultDto>(TestContext.Current.CancellationToken))!.Success;
    }

    private static CkMethodPrincipal Self(string subject) => new(subject, [], ["octo_api"]);

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync<TParameters>(WebApplicationFactory<Program> host,
        CkMethodPrincipal caller, string methodId, string targetRtId, TParameters parameters)
    {
        var dispatcher = host.Services.GetRequiredService<ICkMethodDispatcher>();
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = IdentityMethodFacade.UserCkTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await dispatcher.InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private Task<CkMethodResponse> SetViaMethodAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string targetRtId, string newPassword) =>
        DispatchAsync(host, caller, SystemIdentityCkIds.UserSetPasswordMethodId, targetRtId,
            new UserSetPasswordParameters { NewPassword = newPassword });

    /// <summary>The describer of the host; read the texts under <see cref="EnglishAsTheRequest" /> (the requests carry no culture).</summary>
    private IdentityErrorDescriber Describer()
    {
        using var scope = CreateScope();
        return scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().ErrorDescriber;
    }

    /// <summary>The culture an HTTP request of the test client gets (no Accept-Language): the default, English.</summary>
    private static string EnglishAsTheRequest(Func<string> text)
    {
        var before = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
        try
        {
            return text();
        }
        finally
        {
            CultureInfo.CurrentUICulture = before;
        }
    }

    private IdentityOptions Options()
    {
        using var scope = CreateScope();
        return scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().Options;
    }

    private void AssertNothingReachedTheBroker() =>
        _eventHub.ReceivedCalls().Where(c => c.GetArguments().Any(a => a is CkMethodRequest)).Should()
            .BeEmpty("the password methods run in-process; no method request is sent or published");

    private void AssertCanaryNowhere(string canary)
    {
        _logs.Messages.Should().NotContain(m => m.Contains(canary, StringComparison.Ordinal), "logs");
        _auditMessages.Should().NotContain(m => m.Contains(canary, StringComparison.Ordinal), "audit");
        _activityTags.Should().NotContain(t => t.Contains(canary, StringComparison.Ordinal), "traces");
    }

    private List<Dictionary<string, string>> MethodRecordsFor(string targetRtId) =>
        _methodAudit.Where(d => d.GetValueOrDefault("targetRtId") == targetRtId).ToList();

    private static string NewName() => $"u8414_{Guid.NewGuid():N}";

    private static string Canary() => $"Canary!8414-{Guid.NewGuid():N}";

    private async Task<RtUser?> FindAsync(string userName)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
    }

    /// <summary>
    ///     Makes the user one with external logins only: the hash goes through the store, so the security stamp stays and a
    ///     session signed in before stays valid (<c>UserManager.RemovePasswordAsync</c> would rotate it).
    /// </summary>
    private async Task RemovePasswordAsync(string userName)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var store = (IUserPasswordStore<RtUser>)scope.ServiceProvider.GetRequiredService<IUserStore<RtUser>>();
        var user = (await manager.FindByNameAsync(userName))!;
        await store.SetPasswordHashAsync(user, null, TestContext.Current.CancellationToken);
        (await manager.UpdateAsync(user)).Succeeded.Should().BeTrue();
        (await manager.HasPasswordAsync((await manager.FindByNameAsync(userName))!)).Should().BeFalse();
    }

    private async Task LockOutAsync(string userName)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var user = (await manager.FindByNameAsync(userName))!;
        (await manager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddHours(1))).Succeeded.Should().BeTrue();
    }

    private async Task<RtUser> CreateShadowUserAsync()
    {
        var shadowUserName = $"xt_{NormalizedSystemTenantId}_{Guid.NewGuid():N}";
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var shadow = new RtUserBuilder()
            .WithUserName(shadowUserName)
            .WithEmail($"{shadowUserName}@example.com")
            .WithEmailConfirmed()
            .Build();
        (await userManager.CreateAsync(shadow)).Succeeded.Should().BeTrue();
        return shadow;
    }

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
            {
                owner.Messages.Enqueue(formatter(state, exception) + " " + exception);
                if (state is IEnumerable<KeyValuePair<string, object?>> values)
                {
                    foreach (var value in values)
                    {
                        owner.Messages.Enqueue($"{value.Key}={value.Value}");
                    }
                }
            }
        }
    }

    #endregion
}
