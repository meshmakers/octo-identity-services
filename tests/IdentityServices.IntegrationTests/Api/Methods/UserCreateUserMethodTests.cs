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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7777: the static method <c>User.CreateUser-1</c> served by the identity service. Real MongoDB, the real identity host
///     with <c>Methods:Identity:EnablePasswordMethods=true</c>; the handler runs in a fresh DI scope without an HTTP request, as on
///     the bus, with the principal the host validated. The event repository, the welcome notification and the logger are captured
///     to check the audit record, the invitation and that no password value is written anywhere. The refusal of a new user on the
///     generic paths (GraphQL, ImportRt, blueprint seed) is engine behaviour and is tested in octo-construction-kit-engine and
///     octo-asset-repo-services.
/// </summary>
public class UserCreateUserMethodTests : IntegrationTestBase
{
    private const string InitialPassword = "Canary!Str0ng-7777";
    private static readonly string[] AdminRoles = ["UserManagement"];

    private readonly WebApplicationFactory<Program> _enabled;
    private readonly ConcurrentQueue<CapturedEvent> _events = new();
    private readonly CapturingLoggerProvider _logs = new();
    private readonly IUserEmailInteractionService _mail = Substitute.For<IUserEmailInteractionService>();

    public UserCreateUserMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _enabled = factory.WithWebHostBuilder(b =>
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
                services.RemoveAll<IUserEmailInteractionService>();
                services.AddSingleton(_mail);
            });
        });
    }

    [Fact]
    public void SwitchOff_TheHostRegistersNoHandler_SoTheGatewayAnswersHandlerNotAvailable()
    {
        // The method carries the sensitive initial password: by default (every environment) it is not hosted.
        using var scope = Factory.Services.CreateScope();
        scope.ServiceProvider.GetService<UserCreateUserHandler>().Should().BeNull();
    }

    [Fact]
    public void SwitchOn_TheHostHostsTheHandler()
    {
        using var scope = _enabled.Services.CreateScope();
        scope.ServiceProvider.GetService<UserCreateUserHandler>().Should().NotBeNull();
    }

    [Fact]
    public async Task WithAnInitialPassword_TheUserIsCreatedNormalised_CanSignIn_IsWelcomed_AndTheCallIsAudited()
    {
        var ct = TestContext.Current.CancellationToken;
        var admin = await CreateTestUserAsync(NewUserName(), password: "Test123!");
        var userName = NewUserName();
        var email = $"{userName}@Example.com";

        var outcome = await CreateAsync(Admin(admin), Parameters(userName, email, InitialPassword), ct);

        outcome.Failure.Should().BeNull();
        var stored = await FindAsync(userName);
        stored.Should().NotBeNull();
        outcome.Value!.Value.Should().Be(stored!.RtId.ToString(), "the result is the rtId of the new user");
        stored.NormalizedUserName.Should().Be(userName.ToUpperInvariant());
        stored.Email.Should().Be(email);
        stored.NormalizedEmail.Should().Be(email.ToUpperInvariant());
        stored.FirstName.Should().Be("First");
        stored.LastName.Should().Be("Last");
        stored.SecurityStamp.Should().NotBeNullOrEmpty("the user manager sets the security stamp");
        stored.PasswordHash.Should().NotBeNullOrEmpty();
        stored.PasswordHash.Should().NotContain(InitialPassword);
        (await LoginAndGetAuthenticatedClientAsync(userName, InitialPassword, ct)).Should().NotBeNull();
        await _mail.Received(1).SendWelcomeNotificationAsync(NormalizedSystemTenantId,
            Arg.Is<RtUser>(u => u.UserName == userName));
        await _mail.DidNotReceiveWithAnyArgs().SendWelcomeNotificationWithoutPasswordAsync(default!, default!);

        var audit = _events.Single(e => e.Category == IdentityMethodAuditWriter.Category);
        audit.Details["outcome"].Should().Be("SUCCESS");
        audit.Details["targetRtId"].Should().Be(stored.RtId.ToString());
        audit.Details["userName"].Should().Be(userName);
        audit.Details["withPassword"].Should().Be("true");
        audit.Details["callerSubject"].Should().Be(admin.RtId.ToString());
        audit.TenantId.Should().Be(NormalizedSystemTenantId);
        NoPasswordInAuditOrLogs();
    }

    [Fact]
    public async Task WithoutAPassword_TheUserIsInvited_HasNoPassword_AndGetsTheWelcomeWithoutPassword()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();

        var outcome = await CreateAsync(Admin(), Parameters(userName, $"{userName}@example.com", null), ct);

        outcome.Failure.Should().BeNull();
        var stored = (await FindAsync(userName))!;
        stored.PasswordHash.Should().BeNull("an invited user sets the password through the welcome link");
        stored.SecurityStamp.Should().NotBeNullOrEmpty();
        stored.NormalizedEmail.Should().Be($"{userName}@example.com".ToUpperInvariant());
        await _mail.Received(1).SendWelcomeNotificationWithoutPasswordAsync(NormalizedSystemTenantId,
            Arg.Is<RtUser>(u => u.UserName == userName));
        await _mail.DidNotReceiveWithAnyArgs().SendWelcomeNotificationAsync(default!, default!);
        _events.Single().Details["withPassword"].Should().Be("false");
    }

    [Fact]
    public async Task ABlankPassword_IsAnInvitation_LikeTheRestEndpoint()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();

        (await CreateAsync(Admin(), Parameters(userName, null, "   "), ct)).Failure.Should().BeNull();

        (await FindAsync(userName))!.PasswordHash.Should().BeNull();
        _events.Single().Details["withPassword"].Should().Be("false");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADuplicateUserName_IsRefusedWithTheDeclaredError_AndCreatesNothing(bool otherCasing)
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var existing = await CreateTestUserAsync(userName, password: "Test123!");

        var outcome = await CreateAsync(Admin(),
            Parameters(otherCasing ? userName.ToUpperInvariant() : userName, null, InitialPassword), ct);

        outcome.Failure!.Code.Should().Be(UserCreateUserHandler.UserAlreadyExists);
        outcome.Failure.Parameters.Should().Contain("field", "userName");
        (await FindAsync(userName))!.RtId.Should().Be(existing.RtId, "the existing user is untouched");
        _events.Single().Details["outcome"].Should().Be(UserCreateUserHandler.UserAlreadyExists);
        _events.Single().Details.Should().NotContainKey("targetRtId");
        await _mail.DidNotReceiveWithAnyArgs().SendWelcomeNotificationAsync(default!, default!);
    }

    [Fact]
    public async Task ADuplicateEmail_IsRefusedWithTheDeclaredError_AndCreatesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var existingName = NewUserName();
        await CreateTestUserAsync(existingName, email: $"{existingName}@example.com", password: "Test123!");
        var userName = NewUserName();

        var outcome = await CreateAsync(Admin(),
            Parameters(userName, $"{existingName}@EXAMPLE.com", InitialPassword), ct);

        outcome.Failure!.Code.Should().Be(UserCreateUserHandler.UserAlreadyExists);
        outcome.Failure.Parameters.Should().Contain("field", "email");
        (await FindAsync(userName)).Should().BeNull();
    }

    [Fact]
    public async Task ADuplicateEmail_WithSurroundingBlanks_IsRefusedByTheSharedCreationService()
    {
        // AB#8064: the rule lives in IUserCreationService, which REST POST users shares (409, same code); the handler trims
        // the address and the service compares it normalised.
        var ct = TestContext.Current.CancellationToken;
        var existingName = NewUserName();
        await CreateTestUserAsync(existingName, email: $"{existingName}@example.com", password: "Test123!");
        var userName = NewUserName();

        var outcome = await CreateAsync(Admin(),
            Parameters(userName, $"  {existingName}@Example.COM ", null), ct);

        outcome.Failure!.Code.Should().Be(UserCreateUserHandler.UserAlreadyExists);
        outcome.Failure.Parameters.Should().Contain("field", "email");
        (await FindAsync(userName)).Should().BeNull();
        _events.Single().Details["outcome"].Should().Be(UserCreateUserHandler.UserAlreadyExists);
        await _mail.DidNotReceiveWithAnyArgs().SendWelcomeNotificationWithoutPasswordAsync(default!, default!);
    }

    [Fact]
    public async Task UsersWithoutAnEmail_AreNotCheckedForDuplicates()
    {
        var ct = TestContext.Current.CancellationToken;
        var first = NewUserName();
        var second = NewUserName();

        (await CreateAsync(Admin(), Parameters(first, null, InitialPassword), ct)).Failure.Should().BeNull();
        (await CreateAsync(Admin(), Parameters(second, "  ", InitialPassword), ct)).Failure.Should().BeNull();

        (await FindAsync(second))!.Email.Should().BeNull();
    }

    [Fact]
    public async Task APolicyViolation_NamesTheFailedRules_NeverTheValue_AndCreatesNoUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        const string weak = "wk-ab";

        var outcome = await CreateAsync(Admin(), Parameters(userName, null, weak), ct);

        outcome.Failure!.Code.Should().Be(UserCreateUserHandler.PasswordPolicyViolation);
        outcome.Failure.Details!.Select(d => d.Code).Should().Contain("PasswordTooShort");
        JsonSerializer.Serialize(outcome.Failure).Should().NotContain(weak);
        (await FindAsync(userName)).Should().BeNull("the password is validated before the user is stored");
        _events.Single().Details["outcome"].Should().Be(UserCreateUserHandler.PasswordPolicyViolation);
        _events.SelectMany(e => e.Details.Values).Append(string.Join(' ', _events.Select(e => e.Message)))
            .Should().NotContain(v => v.Contains(weak));
        _logs.Messages.Should().NotContain(m => m.Contains(weak));
    }

    [Fact]
    public async Task AShadowUserName_IsReserved()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"xt_a_{NewUserName()}";

        var outcome = await CreateAsync(Admin(), Parameters(userName, null, InitialPassword), ct);

        outcome.Failure!.Code.Should().Be(UserCreateUserHandler.UserNameReserved);
        (await FindAsync(userName)).Should().BeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AMissingUserName_IsAValidationFailure(string userName)
    {
        var ct = TestContext.Current.CancellationToken;

        var outcome = await CreateAsync(Admin(), Parameters(userName, null, InitialPassword), ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodValidationFailed);
        outcome.Failure.Parameters.Should().Contain("field", "userName");
    }

    [Fact]
    public async Task AUserNameWithCharactersTheUserManagerRejects_IsAValidationFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"bad name {Guid.NewGuid():N}";

        var outcome = await CreateAsync(Admin(), Parameters(userName, null, InitialPassword), ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodValidationFailed);
        outcome.Failure.Parameters.Should().Contain("field", "userName");
        (await FindAsync(userName)).Should().BeNull();
    }

    public static TheoryData<string> UnauthorizedCallers => new() { "no-role", "read-only-scope", "no-principal" };

    [Theory]
    [MemberData(nameof(UnauthorizedCallers))]
    public async Task ACallerWithoutTheAdministrationRule_IsForbidden_AndCreatesNothing(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        CkMethodPrincipal? principal = kind switch
        {
            "no-role" => new CkMethodPrincipal("507f1f77bcf86cd799439012", ["AdminPanelManagement"], ["octo_api"]),
            "read-only-scope" => new CkMethodPrincipal("507f1f77bcf86cd799439012", AdminRoles, ["octo_api.read_only"]),
            _ => null
        };

        var outcome = await CreateAsync(principal, Parameters(userName, null, InitialPassword), ct);

        outcome.Failure!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        (await FindAsync(userName)).Should().BeNull();
        _events.Should().ContainSingle(e => e.Details["outcome"] == CkMethodErrorCodes.MethodForbidden,
            "one audit record per call, also for a refusal");
        NoPasswordInAuditOrLogs();
    }

    [Fact]
    public async Task AServiceToken_WithTheRole_CreatesTheUser_ActorIsTheClient()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();

        var outcome = await CreateAsync(new CkMethodPrincipal(null, AdminRoles, ["octo_api"], "svc-client"),
            Parameters(userName, null, InitialPassword), ct);

        outcome.Failure.Should().BeNull();
        (await FindAsync(userName)).Should().NotBeNull();
        _events.Single().Details["callerSubject"].Should().Be("svc-client");
    }

    [Fact]
    public async Task AForgedCaller_WithoutAValidToken_IsRejectedByTheHost_AndNothingIsCreated()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var invoker = _enabled.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        foreach (var token in new string?[] { null, "" })
        {
            var response = await invoker.InvokeAsync(Request(userName, token), ct);
            response.Success.Should().BeFalse();
            response.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        }

        // The authority is not reachable in this test host, so a token cannot be validated and the host fails closed.
        var forged = Request(userName, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4Iiwicm9sZSI6IlVzZXJNYW5hZ2VtZW50In0.") with
        {
            Caller = new CkMethodCaller { SubjectId = "507f1f77bcf86cd799439012", Roles = ["UserManagement"] }
        };
        var forgedResponse = await invoker.InvokeAsync(forged, ct);
        forgedResponse.Success.Should().BeFalse();
        forgedResponse.Error!.Code.Should().BeOneOf(CkMethodErrorCodes.MethodForbidden, "METHOD_HANDLER_FAILED");

        (await FindAsync(userName)).Should().BeNull("nothing was created");
        _events.Should().BeEmpty("the handler was never called");
    }

    #region Helpers

    private static string NewUserName() => $"m7777_{Guid.NewGuid():N}";

    private static CkMethodPrincipal Admin(RtUser? user = null) =>
        new(user?.RtId.ToString() ?? "507f1f77bcf86cd799439012", AdminRoles, ["octo_api"]);

    private static UserCreateUserParameters Parameters(string userName, string? email, string? password) => new()
    {
        UserName = userName,
        Email = email,
        FirstName = "First",
        LastName = "Last",
        Password = password
    };

    private async Task<RtUser?> FindAsync(string userName)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
    }

    private void NoPasswordInAuditOrLogs()
    {
        _events.SelectMany(e => e.Details.Values).Concat(_events.Select(e => e.Message)).Should()
            .NotContain(v => v.Contains(InitialPassword));
        _logs.Messages.Should().NotContain(m => m.Contains(InitialPassword));
    }

    private async Task<CkMethodOutcome<UserCreateUserResult>> CreateAsync(CkMethodPrincipal? principal,
        UserCreateUserParameters parameters, CancellationToken ct)
    {
        using var scope = _enabled.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<UserCreateUserHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<UserCreateUserParameters>(Request(parameters.UserName, null), parameters)
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, ct);
    }

    private CkMethodRequest Request(string userName, string? token) => new(NormalizedSystemTenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = SystemIdentityCkIds.UserCreateUserMethodId,
        CkTypeId = "System.Identity/User",
        TargetRtId = null,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
        CallerAccessToken = token,
        ParametersJson = JsonSerializer.Serialize(new { userName, password = InitialPassword })
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
