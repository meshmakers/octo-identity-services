using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Methods.Handlers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#5672: <c>User.ChangePassword</c> served by the identity service as its first CK method. Real MongoDB, the real
///     identity host with <c>Methods:Identity:EnablePasswordMethods=true</c>; the handler runs in a fresh DI scope without an
///     HTTP request, as on the bus.
/// </summary>
public class UserChangePasswordMethodTests : IntegrationTestBase
{
    private const string OldPassword = "Test123!";
    private const string NewPassword = "Str0ng!Passw0rd";

    private readonly WebApplicationFactory<Program> _enabled;

    public UserChangePasswordMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        // UseSetting reaches the host configuration before Program reads Methods:Identity (the handler selection happens
        // while the service collection is built, so a config source added later would be too late).
        _enabled = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Methods:Identity:EnablePasswordMethods", "true");
            // The test host has no broker (its event hub cannot open shared command endpoints): drop the bus side of the
            // method host (endpoints, announcement, heartbeat). Registration, validation, the invoker and the handler stay.
            b.ConfigureTestServices(services =>
            {
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }
            });
        });
    }

    [Fact]
    public async Task SwitchOff_TheHostRegistersNoHandlerAndNoMethodHost()
    {
        // the default configuration of every environment: the host exists (the role methods of AB#7776 carry no secret and
        // are hosted without the switch), but no handler of a secret-carrying method is registered
        Factory.Services.GetService<ICkMethodHandlerInvoker>().Should().NotBeNull();
        using var scope = Factory.Services.CreateScope();
        scope.ServiceProvider.GetService<UserChangePasswordHandler>().Should().BeNull();
        await Task.CompletedTask;
    }

    [Fact]
    public void SwitchOn_TheHostHostsTheHandler()
    {
        _enabled.Services.GetService<ICkMethodHandlerInvoker>().Should().NotBeNull();
        using var scope = _enabled.Services.CreateScope();
        scope.ServiceProvider.GetService<UserChangePasswordHandler>().Should().NotBeNull();
    }

    [Fact]
    public async Task Self_ChangesThePassword_NewWorks_OldFails_AndTheRefreshTokensAreRevoked()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        var subject = user.RtId.ToString();
        await CreateOAuthTokenAsync(subject, "m-spa");
        await CreateOAuthTokenAsync(subject, "m-spa");
        var other = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        await CreateOAuthTokenAsync(other.RtId.ToString(), "m-spa");
        var stampBefore = (await FindAsync(userName)).SecurityStamp;
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull();

        var outcome = await ChangeAsync(subject, subject, OldPassword, NewPassword, ct);

        outcome.IsSuccess.Should().BeTrue();
        (await LoginAndGetAuthenticatedClientAsync(userName, NewPassword, ct)).Should().NotBeNull();
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().BeNull();
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(0);
        (await GetValidOAuthTokenCountForSubjectAsync(other.RtId.ToString())).Should().Be(1, "another user is untouched");
        (await FindAsync(userName)).SecurityStamp.Should().NotBe(stampBefore);
    }

    [Fact]
    public async Task WrongCurrentPassword_IsCurrentPasswordInvalid_Counts_AndChangesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        var subject = user.RtId.ToString();
        await CreateOAuthTokenAsync(subject, "m-spa");

        var outcome = await ChangeAsync(subject, subject, "Wr0ng!Passw0rd", NewPassword, ct);

        outcome.Failure!.Code.Should().Be("CURRENT_PASSWORD_INVALID");
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull("the password is unchanged");
        (await GetValidOAuthTokenCountForSubjectAsync(subject)).Should().Be(1);
    }

    [Fact]
    public async Task WrongCurrentPassword_RepeatedUntilTheThreshold_LocksTheUserOut()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        var subject = user.RtId.ToString();

        for (var i = 0; i < 5; i++)
        {
            (await ChangeAsync(subject, subject, "Wr0ng!Passw0rd", NewPassword, ct)).Failure!.Code
                .Should().Be("CURRENT_PASSWORD_INVALID");
        }

        // even the right current password is refused now
        (await ChangeAsync(subject, subject, OldPassword, NewPassword, ct)).Failure!.Code
            .Should().Be("USER_LOCKED_OUT");
    }

    [Fact]
    public async Task LockedOutUser_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword, lockedOut: true);
        var subject = user.RtId.ToString();

        (await ChangeAsync(subject, subject, OldPassword, NewPassword, ct)).Failure!.Code.Should().Be("USER_LOCKED_OUT");
    }

    [Fact]
    public async Task PolicyViolation_NamesTheFailedRules_NeverTheValue_AndChangesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        var subject = user.RtId.ToString();
        const string weak = "abc";

        var outcome = await ChangeAsync(subject, subject, OldPassword, weak, ct);

        outcome.Failure!.Code.Should().Be("PASSWORD_POLICY_VIOLATION");
        outcome.Failure.Details!.Select(d => d.Code).Should().Contain("PasswordTooShort");
        JsonSerializer.Serialize(outcome.Failure).Should().NotContain(weak).And.NotContain(OldPassword);
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull();
    }

    [Fact]
    public async Task AnotherUsersId_IsForbidden_ForAnExistingAndAMissingTarget_Identically()
    {
        var ct = TestContext.Current.CancellationToken;
        var caller = await CreateTestUserAsync(NewUserName(), password: OldPassword);
        var victimName = NewUserName();
        var victim = await CreateTestUserAsync(victimName, password: OldPassword);

        var existing = await ChangeAsync(caller.RtId.ToString(), victim.RtId.ToString(), OldPassword, NewPassword, ct);
        var missing = await ChangeAsync(caller.RtId.ToString(), "507f1f77bcf86cd799439011", OldPassword, NewPassword, ct);

        existing.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        existing.Failure.Parameters.Should().BeEquivalentTo(new Dictionary<string, string> { ["reason"] = "not-self" });
        missing.Failure.Should().BeEquivalentTo(existing.Failure);
        (await LoginAndGetAuthenticatedClientAsync(victimName, OldPassword, ct)).Should().NotBeNull("the victim's password is unchanged");
    }

    [Fact]
    public async Task AServiceToken_HasNoSubject_AndIsForbidden_EvenForAnExistingTarget()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);

        var outcome = await InvokeAsync(user.RtId.ToString(),
            new CkMethodPrincipal(null, ["UserManagement", "AdminPanelManagement"], ["octo_api"], "svc"),
            OldPassword, NewPassword, ct);

        outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull();
    }

    [Fact]
    public async Task AnAdministrator_CannotChangeAnotherUsersPassword_WithThisMethod()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var victim = await CreateTestUserAsync(userName, password: OldPassword);
        var admin = await CreateTestUserAsync(NewUserName(), password: OldPassword);

        var outcome = await InvokeAsync(victim.RtId.ToString(),
            new CkMethodPrincipal(admin.RtId.ToString(), ["UserManagement", "AdminPanelManagement"], ["octo_api"]),
            OldPassword, NewPassword, ct);

        outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull();
    }

    [Fact]
    public async Task ShadowUser_HasNoLocalPassword()
    {
        var ct = TestContext.Current.CancellationToken;
        using (var scope = _enabled.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var shadow = new Shared.TestUtilities.Builders.RtUserBuilder().WithUserName($"xt_a_{NewUserName()}")
                .WithEmail("shadow@example.com").Build();
            (await userManager.CreateAsync(shadow)).Succeeded.Should().BeTrue();
            var subject = shadow.RtId.ToString();

            (await ChangeAsync(subject, subject, OldPassword, NewPassword, ct)).Failure!.Code
                .Should().Be("SHADOW_USER_PASSWORD_NOT_ALLOWED");
        }
    }

    [Fact]
    public async Task AForgedCaller_WithoutAValidToken_IsRejectedByTheHost_AndTheHandlerIsNotCalled()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        var user = await CreateTestUserAsync(userName, password: OldPassword);
        var subject = user.RtId.ToString();
        var invoker = _enabled.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        // No token: refused as METHOD_FORBIDDEN (token-missing). A token that cannot be validated is refused as well; in this
        // test host the authority is not reachable, so the keys cannot be loaded and the host fails closed
        // (METHOD_HANDLER_FAILED, documented in the SDK) - never a success.
        foreach (var token in new string?[] { null, "" })
        {
            var response = await invoker.InvokeAsync(Request(subject, token), ct);
            response.Success.Should().BeFalse();
            response.Error!.Code.Should().Be("METHOD_FORBIDDEN");
        }

        foreach (var token in new[] { "not-a-jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." })
        {
            var response = await invoker.InvokeAsync(Request(subject, token), ct);
            response.Success.Should().BeFalse();
            response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
        }

        // the forged request names the user as caller but the host does not believe it
        var forged = Request(subject, "not-a-jwt") with { Caller = new CkMethodCaller { SubjectId = subject } };
        (await invoker.InvokeAsync(forged, ct)).Success.Should().BeFalse();
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull("nothing changed");
    }

    [Fact]
    public async Task AMethodWithoutHandler_IsNotAvailableOnTheHost()
    {
        var ct = TestContext.Current.CancellationToken;
        var invoker = _enabled.Services.GetRequiredService<ICkMethodHandlerInvoker>();
        var request = Request("507f1f77bcf86cd799439011", "x") with
        {
            MethodId = "System.Identity/User.ResetPassword-1"
        };

        var response = await invoker.InvokeAsync(request, ct);

        response.Error!.Code.Should().Be("METHOD_HANDLER_NOT_AVAILABLE");
    }

    #region Helpers

    private static string NewUserName() => $"m5672_{Guid.NewGuid():N}";

    private async Task<RtUser> FindAsync(string userName)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName))!;
    }

    private Task<CkMethodOutcome> ChangeAsync(string callerSubject, string target, string current, string next,
        CancellationToken ct) =>
        InvokeAsync(target, new CkMethodPrincipal(callerSubject, [], ["octo_api"]), current, next, ct);

    /// <summary>Runs the handler in a new DI scope without an HTTP request, with the principal the host validated.</summary>
    private async Task<CkMethodOutcome> InvokeAsync(string target, CkMethodPrincipal principal, string current,
        string next, CancellationToken ct)
    {
        using var scope = _enabled.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<UserChangePasswordHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<UserChangePasswordParameters>(Request(target, null),
            new UserChangePasswordParameters { CurrentPassword = current, NewPassword = next })
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, ct);
    }

    private CkMethodRequest Request(string target, string? token) => new(NormalizedSystemTenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = SystemIdentityCkIds.UserChangePasswordMethodId,
        CkTypeId = "System.Identity/User",
        TargetRtId = target,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
        CallerAccessToken = token,
        ParametersJson = JsonSerializer.Serialize(new { currentPassword = OldPassword, newPassword = NewPassword })
    };

    #endregion
}
