using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
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

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8413: <c>POST users</c> and <c>POST users/ResetPassword</c> are facades of <c>User.CreateUser-1</c> and
///     <c>User.ResetPassword-1</c>, also while <c>Methods:Identity:EnablePasswordMethods</c> keeps the password methods off the
///     bus (production gate 2026-10-23, until B0). Real MongoDB, real identity host. The event hub is a substitute that records
///     every call: the password must never reach it. Logs, audit events and activity tags are captured for the canary.
///     The REST contract itself is covered unchanged by <see cref="UsersCreateTests" />, <see cref="ShadowUserPasswordTests" />,
///     <see cref="CredentialsNotInUrlTests" /> (AB#8008: no password in the URL) and <c>PasswordChangeRevokesSessionsTests</c>.
/// </summary>
public class UserPasswordRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";
    private const string OldPassword = "Test123!";

    private readonly ConcurrentQueue<Dictionary<string, string>> _methodAudit = new();
    private readonly ConcurrentQueue<string> _auditMessages = new();
    private readonly CapturingLoggerProvider _logs = new();
    private readonly ConcurrentQueue<string> _activityTags = new();
    private readonly ActivityListener _activities;
    private readonly IEventRepository _events = Substitute.For<IEventRepository>();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly IUserEmailInteractionService _mail = Substitute.For<IUserEmailInteractionService>();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public UserPasswordRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
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

    #region ResetPassword

    [Theory]
    [MemberData(nameof(PasswordMethodSwitch))]
    public async Task RestReset_OfALockedOutUser_LiftsTheLockout_RevokesSessions_AuditsOnce_SendsOneMail_NothingOnTheBus(
        string enablePasswordMethods)
    {
        var host = Host(enablePasswordMethods);
        var ct = TestContext.Current.CancellationToken;
        var newPassword = Canary();
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        var subject = user.RtId.ToString();
        await LockOutAsync(user.UserName!);
        await CreateOAuthTokenAsync(subject, "m-spa");
        (await FindAsync(user.UserName!))!.LockoutEnd.Should().NotBeNull("the precondition: the user is locked out");
        var actor = Guid.NewGuid().ToString("N");
        using var client = RestClient(host, actor, [UserManagement]);

        var response = await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName = user.UserName, password = newPassword }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        (await response.Content.ReadAsStringAsync(ct)).Should().BeEmpty();
        var stored = (await FindAsync(user.UserName!))!;
        stored.LockoutEnd.Should().BeNull("the method lifts the lockout (REST behaviour change, CHANGELOG)");
        stored.AccessFailedCount.Should().Be(0);
        (await LoginAndGetAuthenticatedClientAsync(user.UserName!, newPassword, ct)).Should().NotBeNull();
        (await LoginAndGetAuthenticatedClientAsync(user.UserName!, OldPassword, ct)).Should().BeNull();
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(0, "old refresh tokens fail");

        var record = MethodRecordsFor(subject).Should().ContainSingle().Subject;
        record["methodId"].Should().Be(SystemIdentityCkIds.UserResetPasswordMethodId);
        record["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        record["lockoutLifted"].Should().Be("true");
        record["callerSubject"].Should().Be(actor);

        // Until AB#7775 the facade sends the notification; when the method sends it, this count catches a double e-mail.
        await _mail.Received(1).SendPasswordResetNotificationAsync(Arg.Any<string>(),
            Arg.Is<RtUser>(u => u.RtId == user.RtId));
        AssertNothingReachedTheBroker();
        AssertCanaryNowhere(newPassword);
    }

    [Fact]
    public async Task SwitchOff_ResetPasswordAndCreateUser_RunInThisProcess_ButAreNotOfferedOnTheBus()
    {
        var host = Host("false");

        var transport = host.Services.GetRequiredService<ICkInProcessMethodTransport>();
        transport.CanHandle(SystemIdentityCkIds.UserResetPasswordMethodId).Should().BeTrue();
        transport.CanHandle(SystemIdentityCkIds.UserCreateUserMethodId).Should().BeTrue();
        // Not announced (HandleLocalOnly): the bus selection of the host excludes both, so the GraphQL gateway keeps
        // answering METHOD_HANDLER_NOT_AVAILABLE (registration: IdentityMethodHostTests).
        IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions()).Select(h => h.MethodId).Should()
            .NotContain([SystemIdentityCkIds.UserResetPasswordMethodId, SystemIdentityCkIds.UserCreateUserMethodId]);
    }

    [Theory]
    [MemberData(nameof(PasswordMethodSwitch))]
    public async Task RestReset_PolicyViolation_Is400WithCodeAndDescription_AndChangesNothing(string enablePasswordMethods)
    {
        var host = Host(enablePasswordMethods);
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewName(), password: OldPassword);
        var stampBefore = (await FindAsync(user.UserName!))!.SecurityStamp;
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);

        var response = await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName = user.UserName, password = "short" }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        var details = body.GetProperty("details").EnumerateArray().ToList();
        details.Should().Contain(d => d.GetProperty("code").GetString() == "PasswordTooShort");
        details.Should().OnlyContain(d => !string.IsNullOrEmpty(d.GetProperty("description").GetString()),
            "the REST body keeps the description of every failed rule");
        (await FindAsync(user.UserName!))!.SecurityStamp.Should().Be(stampBefore);
        await _mail.DidNotReceiveWithAnyArgs().SendPasswordResetNotificationAsync(default!, default!);
        MethodRecordsFor(user.RtId.ToString()).Should().ContainSingle()
            .Which["outcome"].Should().Be(UserResetPasswordHandler.PasswordPolicyViolation);
    }

    #endregion

    #region CreateUser

    [Theory]
    [MemberData(nameof(PasswordMethodSwitch))]
    public async Task RestCreate_RunsTheMethod_OneAuditEvent_OneWelcomeMail_NothingOnTheBus(string enablePasswordMethods)
    {
        var host = Host(enablePasswordMethods);
        var ct = TestContext.Current.CancellationToken;
        var password = Canary();
        var name = NewName();
        var actor = Guid.NewGuid().ToString("N");
        using var client = RestClient(host, actor, [UserManagement]);

        var response = await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = $"  {name} ", email = $" {name}@Example.com ", firstName = "Ada", lastName = "Lovelace", password },
            ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(ct)).Should().BeEmpty("the REST answer stays 200 without a body");
        var created = (await FindAsync(name))!;
        created.Should().NotBeNull("the method trims the user name");
        created.Email.Should().Be($"{name}@Example.com");
        created.FirstName.Should().Be("Ada");
        created.ResetPasswordOnLogin.Should().BeFalse();
        (await LoginAndGetAuthenticatedClientAsync(name, password, ct)).Should().NotBeNull();
        var record = MethodRecordsFor(created.RtId.ToString()).Should().ContainSingle().Subject;
        record["methodId"].Should().Be(SystemIdentityCkIds.UserCreateUserMethodId);
        record["withPassword"].Should().Be("true");
        record["callerSubject"].Should().Be(actor);
        await _mail.Received(1).SendWelcomeNotificationAsync(Arg.Any<string>(), Arg.Is<RtUser>(u => u.RtId == created.RtId));
        AssertNothingReachedTheBroker();
        AssertCanaryNowhere(password);
    }

    [Fact]
    public async Task RestCreate_KeepsTheRestOnlyFlag_ResetPasswordOnLogin()
    {
        var host = Host();
        var name = NewName();
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);

        var response = await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name, email = $"{name}@example.com", password = OldPassword, resetPasswordOnLogin = true },
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK,
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        (await FindAsync(name))!.ResetPasswordOnLogin.Should().BeTrue();
    }

    [Fact]
    public async Task RestCreate_ResetPasswordOnLoginWriteFails_Is500_NotASilentSuccess()
    {
        // CodeRabbit on #269: the flag is a second write after User.CreateUser. A failed write must not answer 200, or
        // the user keeps the administrator-chosen password without being told to change it.
        var host = Host(configureServices: services =>
            services.AddScoped<IUserValidator<RtUser>, RefuseResetPasswordOnLoginValidator>());
        var name = NewName();
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);

        var response = await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name, email = $"{name}@example.com", password = OldPassword, resetPasswordOnLogin = true },
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.InternalServerError, body);
        body.Should().Contain("ResetPasswordOnLogin could not be set");
        var created = await FindAsync(name);
        created.Should().NotBeNull("User.CreateUser stored the user before the flag write failed");
        created!.ResetPasswordOnLogin.Should().BeFalse();
    }

    #endregion

    #region REST and the method give the same end state (switch on: the GraphQL path exists)

    [Fact]
    public async Task Parity_CreateWithPassword_DuplicateNameAndEmail_PolicyViolation()
    {
        var host = Host("true");
        var ct = TestContext.Current.CancellationToken;
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);
        var admin = Admin();

        // create with password
        var restName = NewName();
        var methodName = NewName();
        (await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = restName, email = $"{restName}@example.com", password = OldPassword }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await CreateViaMethodAsync(host, admin, methodName, $"{methodName}@example.com", OldPassword)).Success.Should()
            .BeTrue();
        var restUser = (await FindAsync(restName))!;
        var methodUser = (await FindAsync(methodName))!;
        (restUser.PasswordHash != null).Should().Be(methodUser.PasswordHash != null);
        restUser.NormalizedEmail.Should().Be($"{restName}@example.com".ToUpperInvariant());
        methodUser.NormalizedEmail.Should().Be($"{methodName}@example.com".ToUpperInvariant());

        // duplicate user name: 409 field userName / USER_ALREADY_EXISTS field userName
        var restDuplicate = await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = restName, email = $"{NewName()}@example.com", password = OldPassword }, ct);
        restDuplicate.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await restDuplicate.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("field").GetString().Should()
            .Be("userName");
        var methodDuplicate = await CreateViaMethodAsync(host, admin, methodName, $"{NewName()}@example.com", OldPassword);
        methodDuplicate.Error!.Code.Should().Be(UserCreateUserHandler.UserAlreadyExists);
        methodDuplicate.Error.Parameters.Should().Contain("field", "userName");

        // duplicate e-mail: 409 field email / USER_ALREADY_EXISTS field email
        var restDuplicateMail = await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = NewName(), email = $"{restName}@example.com", password = OldPassword }, ct);
        restDuplicateMail.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await restDuplicateMail.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("field").GetString().Should()
            .Be("email");
        (await CreateViaMethodAsync(host, admin, NewName(), $"{methodName}@example.com", OldPassword)).Error!.Parameters
            .Should().Contain("field", "email");

        // policy violation: nothing is created either way
        var weakRest = NewName();
        var weakMethod = NewName();
        (await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = weakRest, email = $"{weakRest}@example.com", password = "short" }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.BadRequest);
        (await CreateViaMethodAsync(host, admin, weakMethod, $"{weakMethod}@example.com", "short")).Error!.Code.Should()
            .Be(UserCreateUserHandler.PasswordPolicyViolation);
        (await FindAsync(weakRest)).Should().BeNull();
        (await FindAsync(weakMethod)).Should().BeNull();
    }

    [Fact]
    public async Task Parity_InvitationWithoutPassword_IsMethodOnly_RestKeepsRequiringThePassword()
    {
        var host = Host("true");
        var ct = TestContext.Current.CancellationToken;
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);
        var restName = NewName();
        var methodName = NewName();

        // RegisterUserDto.Password is [Required]: REST answers model validation 400 as before, nothing is created.
        (await client.PostAsJsonAsync(TenantApiUrl("users"), new { name = restName, email = $"{restName}@example.com" }, ct))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await CreateViaMethodAsync(host, Admin(), methodName, $"{methodName}@example.com", null)).Success.Should()
            .BeTrue();

        (await FindAsync(restName)).Should().BeNull();
        (await FindAsync(methodName))!.PasswordHash.Should().BeNull();
    }

    [Fact]
    public async Task Parity_ResetPassword_SuccessUnknownUserAndShadowUser()
    {
        var host = Host("true");
        var ct = TestContext.Current.CancellationToken;
        using var client = RestClient(host, Guid.NewGuid().ToString("N"), [UserManagement]);
        var admin = Admin();
        var restUser = await CreateTestUserAsync(NewName(), password: OldPassword);
        var methodUser = await CreateTestUserAsync(NewName(), password: OldPassword);
        await LockOutAsync(restUser.UserName!);
        await LockOutAsync(methodUser.UserName!);

        (await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName = restUser.UserName, password = "N3w!Parity-8413" }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await ResetViaMethodAsync(host, admin, methodUser.RtId.ToString(), "N3w!Parity-8413")).Success.Should().BeTrue();
        foreach (var name in new[] { restUser.UserName!, methodUser.UserName! })
        {
            var stored = (await FindAsync(name))!;
            stored.LockoutEnd.Should().BeNull();
            stored.AccessFailedCount.Should().Be(0);
            (await LoginAndGetAuthenticatedClientAsync(name, "N3w!Parity-8413", ct)).Should().NotBeNull();
        }

        // unknown user: 404 / METHOD_TARGET_NOT_FOUND
        (await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName = NewName(), password = "N3w!Parity-8413" }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await ResetViaMethodAsync(host, admin, OctoObjectId.GenerateNewId().ToString(), "N3w!Parity-8413")).Error!.Code
            .Should().Be(CkMethodErrorCodes.MethodTargetNotFound);

        // shadow user: 400 / SHADOW_USER_PASSWORD_NOT_ALLOWED, no password either way
        var shadow = await CreateShadowUserAsync();
        var restShadow = await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName = shadow.UserName, password = "N3w!Parity-8413" }, ct);
        restShadow.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await ResetViaMethodAsync(host, admin, shadow.RtId.ToString(), "N3w!Parity-8413")).Error!.Code.Should()
            .Be(UserResetPasswordHandler.ShadowUserPasswordNotAllowed);
        (await FindAsync(shadow.UserName!))!.PasswordHash.Should().BeNull();
    }

    #endregion

    #region Helpers

    private WebApplicationFactory<Program> Host(string? enablePasswordMethods = null,
        Action<IServiceCollection>? configureServices = null)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (enablePasswordMethods != null)
            {
                b.UseSetting("Methods:Identity:EnablePasswordMethods", enablePasswordMethods);
            }

            b.ConfigureTestServices(services =>
            {
                // The test host has no broker: drop the bus side of the method host (announcement, heartbeat). Registration,
                // validation, invoker, dispatcher and handlers stay.
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }

                services.AddSingleton(_events);
                services.RemoveAll<IDistributionEventHubService>();
                services.AddSingleton(_eventHub);
                services.RemoveAll<IUserEmailInteractionService>();
                services.AddSingleton(_mail);
                services.AddLogging(l => l.AddProvider(_logs));
                configureServices?.Invoke(services);
            });
        });
        _hosts.Add(host);
        return host;
    }

    private static HttpClient RestClient(WebApplicationFactory<Program> host, string subject, string[] roles)
    {
        var client = host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, subject);
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        foreach (var role in roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        return client;
    }

    private static CkMethodPrincipal Admin() =>
        new(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync<TParameters>(WebApplicationFactory<Program> host,
        CkMethodPrincipal caller, string methodId, string? targetRtId, TParameters parameters)
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

    private Task<CkMethodResponse> CreateViaMethodAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string userName, string email, string? password) =>
        DispatchAsync(host, caller, SystemIdentityCkIds.UserCreateUserMethodId, null,
            new UserCreateUserParameters { UserName = userName, Email = email, Password = password });

    private Task<CkMethodResponse> ResetViaMethodAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string targetRtId, string newPassword) =>
        DispatchAsync(host, caller, SystemIdentityCkIds.UserResetPasswordMethodId, targetRtId,
            new UserResetPasswordParameters { NewPassword = newPassword });

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

    private static string NewName() => $"u8413_{Guid.NewGuid():N}";

    private static string Canary() => $"Canary!8413-{Guid.NewGuid():N}";

    private async Task<RtUser?> FindAsync(string userName)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
    }

    private async Task LockOutAsync(string userName)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var user = (await manager.FindByNameAsync(userName))!;
        (await manager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddHours(1))).Succeeded.Should().BeTrue();
        await manager.AccessFailedAsync(user);
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

    /// <summary>Lets the create pass and refuses the later update that sets <c>ResetPasswordOnLogin</c>.</summary>
    private sealed class RefuseResetPasswordOnLoginValidator : IUserValidator<RtUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<RtUser> manager, RtUser user) =>
            Task.FromResult(user.ResetPasswordOnLogin
                ? IdentityResult.Failed(new IdentityError { Code = "TestRefused", Description = "Refused by the test." })
                : IdentityResult.Success);
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
