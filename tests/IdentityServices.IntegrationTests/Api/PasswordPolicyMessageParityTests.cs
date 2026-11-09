using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api;

/// <summary>
///     AB#8523: one password that breaks several rules gets the same password-policy messages on every path — the User
///     methods (<c>PASSWORD_POLICY_VIOLATION</c> envelope, texts rebuilt by <see cref="PasswordPolicyErrorDescriber" />),
///     REST <c>POST users</c> and <c>POST users/ResetPassword</c> (code + description) and the account page's
///     <c>set-password</c> and <c>change-password</c> (descriptions). Same request culture on every path. Guards against a
///     REST or account path building its own texts again (the change itself: AB#8415, commit 33d0dbbe).
/// </summary>
public class PasswordPolicyMessageParityTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";
    private const string OldPassword = "Test123!";

    /// <summary>Too short, no digit, no non-alphanumeric character, no upper-case letter.</summary>
    private const string WeakPassword = "abc";

    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public PasswordPolicyMessageParityTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public static TheoryData<string> Cultures => new() { "en", "de" };

    /// <summary>Every derived host keeps configuration file watchers; dispose them (CI allows 128 inotify instances).</summary>
    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    [Theory]
    [MemberData(nameof(Cultures))]
    public async Task WeakPassword_RestAndAccountPage_ShowTheMessagesOfTheUserMethods(string culture)
    {
        var host = Host();
        var ct = TestContext.Current.CancellationToken;

        // The User methods: every password method refuses with the same codes; the texts come from the describer.
        var admin = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);
        var createEnvelope = await DispatchAsync(host, admin, SystemIdentityCkIds.UserCreateUserMethodId, null,
            new UserCreateUserParameters
            {
                UserName = NewName(), Email = $"{NewName()}@example.com", Password = WeakPassword
            });
        var methodUser = await CreateTestUserAsync(NewName(), password: OldPassword);
        var resetEnvelope = await DispatchAsync(host, admin, SystemIdentityCkIds.UserResetPasswordMethodId,
            methodUser.RtId.ToString(), new UserResetPasswordParameters { NewPassword = WeakPassword });
        var self = new CkMethodPrincipal(methodUser.RtId.ToString(), [], ["octo_api"]);
        var changeEnvelope = await DispatchAsync(host, self, SystemIdentityCkIds.UserChangePasswordMethodId,
            methodUser.RtId.ToString(),
            new UserChangePasswordParameters { CurrentPassword = OldPassword, NewPassword = WeakPassword });

        foreach (var envelope in new[] { createEnvelope, resetEnvelope, changeEnvelope })
        {
            envelope.Success.Should().BeFalse();
            envelope.Error!.Code.Should().Be(UserCreateUserHandler.PasswordPolicyViolation);
        }

        var codes = Codes(createEnvelope);
        codes.Should().Contain(["PasswordTooShort", "PasswordRequiresDigit", "PasswordRequiresNonAlphanumeric"],
            "the password breaks several rules");
        Codes(resetEnvelope).Should().BeEquivalentTo(codes);
        Codes(changeEnvelope).Should().BeEquivalentTo(codes);
        var expected = InCulture(culture, () => Describe(host, createEnvelope.Error!));
        expected.Should().OnlyContain(e => !string.IsNullOrWhiteSpace(e.Description) && e.Description != e.Code,
            "every failed rule has a text of the describer, not its code");

        // REST POST users and POST users/ResetPassword: code + description pairs.
        using var rest = CultureClient(host, culture);
        rest.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        rest.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, Guid.NewGuid().ToString("N"));
        rest.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        rest.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, UserManagement);
        var restName = NewName();
        var restCreate = await RestDetailsAsync(await rest.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = restName, email = $"{restName}@example.com", password = WeakPassword }, ct));
        var restUser = await CreateTestUserAsync(NewName(), password: OldPassword);
        var restReset = await RestDetailsAsync(await rest.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName = restUser.UserName, password = WeakPassword }, ct));

        restCreate.Should().BeEquivalentTo(expected, "REST POST users shows the texts of the User method");
        restReset.Should().BeEquivalentTo(expected, "REST POST users/ResetPassword shows the texts of the User method");

        // Account page set-password and change-password: the descriptions.
        var pageUser = await CreateTestUserAsync(NewName(), password: OldPassword);
        using var page = await SignInAsync(host, culture, pageUser.UserName!, OldPassword);
        var change = await PageErrorsAsync(await page.PostAsJsonAsync(ManageApiUrl("change-password"),
            new ChangePasswordRequestDto
            {
                CurrentPassword = OldPassword, NewPassword = WeakPassword, ConfirmPassword = WeakPassword
            }, ct));
        await RemovePasswordAsync(pageUser.UserName!); // a user with external logins only may set a password
        var set = await PageErrorsAsync(await page.PostAsJsonAsync(ManageApiUrl("set-password"),
            new SetPasswordRequestDto { NewPassword = WeakPassword, ConfirmPassword = WeakPassword }, ct));

        var descriptions = expected.Select(e => e.Description).ToList();
        change.Should().BeEquivalentTo(descriptions, "the account page change-password shows the texts of the User method");
        set.Should().BeEquivalentTo(descriptions, "the account page set-password shows the texts of the User method");
    }

    #region Helpers

    private sealed record Message(string Code, string Description);

    private WebApplicationFactory<Program> Host()
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Methods:Identity:EnablePasswordMethods", "true");
            b.ConfigureTestServices(services =>
            {
                // The test host has no broker: drop the bus side of the method host (announcement, heartbeat).
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }

                services.RemoveAll<IDistributionEventHubService>();
                services.AddSingleton(Substitute.For<IDistributionEventHubService>());
                services.RemoveAll<IUserEmailInteractionService>();
                services.AddSingleton(Substitute.For<IUserEmailInteractionService>());
            });
        });
        _hosts.Add(host);
        return host;
    }

    private static HttpClient CultureClient(WebApplicationFactory<Program> host, string culture)
    {
        var client = host.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = true, AllowAutoRedirect = false });
        client.DefaultRequestHeaders.AcceptLanguage.Add(new StringWithQualityHeaderValue(culture));
        return client;
    }

    private static async Task<HttpClient> SignInAsync(WebApplicationFactory<Program> host, string culture,
        string userName, string password)
    {
        var client = CultureClient(host, culture);
        var response = await client.PostAsJsonAsync(AuthApiUrl("login"),
            new { Username = userName, Password = password, RememberLogin = true }, TestContext.Current.CancellationToken);
        (await response.Content.ReadFromJsonAsync<LoginResultDto>(TestContext.Current.CancellationToken))!.Success
            .Should().BeTrue();
        return client;
    }

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

    private static List<string> Codes(CkMethodResponse envelope) =>
        (envelope.Error!.Details ?? []).Select(d => d.Code!).ToList();

    /// <summary>The texts of a method envelope as a REST facade rebuilds them, read with the host's user manager.</summary>
    private static List<Message> Describe(WebApplicationFactory<Program> host, CkMethodError error)
    {
        using var scope = host.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        return PasswordPolicyErrorDescriber.Describe(userManager, error)
            .Select(e => new Message(e.Code, e.Description)).ToList();
    }

    /// <summary>Runs <paramref name="read" /> in the UI culture the request localization gives an HTTP request.</summary>
    private static T InCulture<T>(string culture, Func<T> read)
    {
        var before = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
        try
        {
            return read();
        }
        finally
        {
            CultureInfo.CurrentUICulture = before;
        }
    }

    private static async Task<List<Message>> RestDetailsAsync(HttpResponseMessage response)
    {
        var ct = TestContext.Current.CancellationToken;
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest, await response.Content.ReadAsStringAsync(ct));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        return body.GetProperty("details").EnumerateArray()
            .Select(d => new Message(d.GetProperty("code").GetString()!, d.GetProperty("description").GetString()!))
            .ToList();
    }

    private static async Task<List<string>> PageErrorsAsync(HttpResponseMessage response)
    {
        var body = (await response.Content.ReadFromJsonAsync<PasswordResultDto>(TestContext.Current.CancellationToken))!;
        body.Success.Should().BeFalse();
        return body.Errors!.ToList();
    }

    /// <summary>
    ///     Makes the user one with external logins only: the hash goes through the store, so the security stamp stays and
    ///     the signed-in page session stays valid.
    /// </summary>
    private async Task RemovePasswordAsync(string userName)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var store = (IUserPasswordStore<RtUser>)scope.ServiceProvider.GetRequiredService<IUserStore<RtUser>>();
        var user = (await manager.FindByNameAsync(userName))!;
        await store.SetPasswordHashAsync(user, null, TestContext.Current.CancellationToken);
        (await manager.UpdateAsync(user)).Succeeded.Should().BeTrue();
    }

    private static string NewName() => $"u8523_{Guid.NewGuid():N}";

    #endregion
}
