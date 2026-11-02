using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using OtpNet;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
///     AB#7854 — sign-in attempts are counted atomically and rate-limited, so passwords and second-factor codes
///     cannot be guessed in parallel or through a child tenant.
/// </summary>
/// <remarks>
///     <para>
///         The failure counter, the lockout and the recovery codes live on the user document. Before AB#7854 every
///         request read the user, changed it in memory and wrote the whole document back in a separate transaction —
///         last write wins: N parallel wrong codes raised the counter by about one, and a recovery code could be
///         redeemed by two parallel requests.
///     </para>
///     <para>
///         The tests drive the real <see cref="UserManager{TUser}" /> (one scope per parallel attempt, each with its
///         own copy of the user, exactly like parallel HTTP requests) and the real HTTP endpoints against MongoDB.
///     </para>
/// </remarks>
public class SignInAttemptConcurrencyTests : IntegrationTestBase
{
    private const int ParallelAttempts = 4;

    public SignInAttemptConcurrencyTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private string SourceTenantId => NormalizedSystemTenantId;

    #region Atomic counting (UserManager)

    [Fact]
    public async Task ParallelAccessFailures_AreAllCounted()
    {
        var user = await CreateTestUserAsync($"atomic_count_{Guid.NewGuid():N}");

        await Task.WhenAll(Enumerable.Range(0, ParallelAttempts).Select(_ => FailOnceAsync(user.RtId)));

        var stored = await FindUserAsync(user.RtId);
        stored.AccessFailedCount.Should().Be(ParallelAttempts,
            "every failed attempt counts, however many run at the same time");
        stored.LockoutEnd.Should().BeNull("the threshold (5) was not reached");
    }

    [Fact]
    public async Task ParallelAccessFailures_ReachingTheThreshold_LockTheUserOut()
    {
        var user = await CreateTestUserAsync($"atomic_lock_{Guid.NewGuid():N}");
        var threshold = GetIdentityOptions().Lockout.MaxFailedAccessAttempts;

        await Task.WhenAll(Enumerable.Range(0, threshold).Select(_ => FailOnceAsync(user.RtId)));

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var stored = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
        (await userManager.IsLockedOutAsync(stored)).Should().BeTrue(
            "{0} parallel failures reach the lockout threshold", threshold);
        stored.AccessFailedCount.Should().Be(0, "the counter restarts once the lockout is set (framework arithmetic)");
    }

    [Fact]
    public async Task AccessFailed_UpdatesTheCallersCopy_SoTheLockoutIsSeenInTheSameRequest()
    {
        var user = await CreateTestUserAsync($"atomic_copy_{Guid.NewGuid():N}");
        var threshold = GetIdentityOptions().Lockout.MaxFailedAccessAttempts;

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var copy = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
        for (var i = 0; i < threshold; i++)
        {
            (await userManager.AccessFailedAsync(copy)).Succeeded.Should().BeTrue();
        }

        (await userManager.IsLockedOutAsync(copy)).Should().BeTrue(
            "SignInManager asks IsLockedOutAsync on the same instance right after AccessFailedAsync");
    }

    [Fact]
    public async Task ResetAccessFailedCount_ClearsTheStoredCounter_EvenWhenTheCallersCopyIsStale()
    {
        var user = await CreateTestUserAsync($"atomic_reset_{Guid.NewGuid():N}");

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var staleCopy = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
        await FailOnceAsync(user.RtId);
        await FailOnceAsync(user.RtId);

        (await userManager.ResetAccessFailedCountAsync(staleCopy)).Succeeded.Should().BeTrue();

        (await FindUserAsync(user.RtId)).AccessFailedCount.Should().Be(0,
            "a successful sign-in resets what is stored, not what an old copy believed");
    }

    [Fact]
    public async Task ParallelRecoveryCodeRedemption_SucceedsExactlyOnce()
    {
        var user = await CreateTestUserAsync($"atomic_rec_{Guid.NewGuid():N}");
        string code;
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var copy = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
            // Stored normalized (no hyphen), as the sign-in endpoint passes it on.
            code = (await userManager.GenerateNewTwoFactorRecoveryCodesAsync(copy, 10))!.First().Replace("-", "");
        }

        var results = await Task.WhenAll(Enumerable.Range(0, ParallelAttempts).Select(async _ =>
        {
            using var scope = CreateScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var copy = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
            return (await userManager.RedeemTwoFactorRecoveryCodeAsync(copy, code)).Succeeded;
        }));

        results.Count(r => r).Should().Be(1, "a recovery code is single-use, also under concurrency");
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var copy = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
            (await userManager.CountRecoveryCodesAsync(copy)).Should().Be(9);
        }
    }

    #endregion

    #region HTTP: local second factor

    [Fact]
    public async Task ParallelWrongTotpCodes_EveryEvaluatedAttemptCounts_AndTheUserEndsLockedOut()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"atomic_totp_{Guid.NewGuid():N}";
        var user = await CreateTestUserAsync(userName, password: DefaultPassword);
        var totp = await EnableAuthenticatorAsync(userName, ct);
        var threshold = GetIdentityOptions().Lockout.MaxFailedAccessAttempts;

        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, SourceTenantId, userName, ct)).RequiresTwoFactor.Should().BeTrue();

        // Fewer parallel codes than the threshold: none of them may be lost.
        var responses = await Task.WhenAll(Enumerable.Range(0, threshold - 1).Select(_ =>
            browser.PostAsJsonAsync(AuthApiUrl("login-2fa", SourceTenantId),
                new TwoFactorLoginRequestDto { Code = WrongCode(totp) }, ct)));

        var evaluated = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
        responses.Count(r => r.StatusCode == HttpStatusCode.TooManyRequests).Should().Be(responses.Length - evaluated,
            "an attempt is either evaluated or refused by the per-account limit, nothing else");
        (await FindUserAsync(user.RtId)).AccessFailedCount.Should().Be(evaluated,
            "every evaluated wrong code counts against the lockout");

        // Keep guessing one at a time: the lockout comes after the threshold, counting the parallel ones too.
        var lockedOut = false;
        for (var i = evaluated; i < threshold && !lockedOut; i++)
        {
            var response = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", SourceTenantId),
                new TwoFactorLoginRequestDto { Code = WrongCode(totp) }, ct);
            var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
            lockedOut = result!.ErrorMessage == "Account is locked out";
        }

        lockedOut.Should().BeTrue("the user is locked out after {0} wrong codes in total", threshold);
        var valid = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", SourceTenantId),
            new TwoFactorLoginRequestDto { Code = totp.ComputeTotp() }, ct);
        (await valid.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!.Success.Should().BeFalse(
            "a locked-out user cannot complete the sign-in, not even with the right code");
    }

    #endregion

    #region Cross-tenant password

    [Fact]
    public async Task CrossTenantPasswordFailures_CountAgainstTheSourceUser_AndLockItOut()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"atomic_xt_{Guid.NewGuid():N}";
        var user = await CreateTestUserAsync(userName, password: DefaultPassword);
        var threshold = GetIdentityOptions().Lockout.MaxFailedAccessAttempts;

        var browser = CreateCookieClient();
        var first = await LoginAsync(browser, childTenantId, userName, "Wrong-Password-1", ct);
        first.Success.Should().BeFalse();
        (await FindUserAsync(user.RtId)).AccessFailedCount.Should().Be(1,
            "a wrong password for the parent-tenant user, typed on the child tenant, counts against that user");

        for (var i = 1; i < threshold; i++)
        {
            await LoginAsync(browser, childTenantId, userName, "Wrong-Password-1", ct);
        }

        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var stored = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
            (await userManager.IsLockedOutAsync(stored)).Should().BeTrue(
                "{0} wrong passwords through the child tenant lock the source user out", threshold);
        }

        var correct = await LoginAsync(browser, childTenantId, userName, DefaultPassword, ct);
        correct.Success.Should().BeFalse("a locked-out source user cannot sign in through a child tenant");
        (await browser.GetAsync(ManageApiUrl("profile", childTenantId), ct)).StatusCode
            .Should().NotBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task CrossTenantPasswordSuccess_ResetsTheSourceUsersCounter()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"atomic_xtok_{Guid.NewGuid():N}";
        var user = await CreateTestUserAsync(userName, password: DefaultPassword);

        var browser = CreateCookieClient();
        await LoginAsync(browser, childTenantId, userName, "Wrong-Password-1", ct);
        (await FindUserAsync(user.RtId)).AccessFailedCount.Should().Be(1);

        (await LoginAsync(browser, childTenantId, userName, DefaultPassword, ct)).Success.Should().BeTrue();

        (await FindUserAsync(user.RtId)).AccessFailedCount.Should().Be(0,
            "a successful password sign-in resets the counter, as a local sign-in does");
    }

    #endregion

    #region Rate limits (HTTP)

    [Fact]
    public async Task PasswordLogin_MoreAttemptsPerAccountThanAllowed_IsAnswered429WithRetryAfter()
    {
        var ct = TestContext.Current.CancellationToken;
        using var limited = CreateLimitedFactory(perAccount: 3, perClientIp: 1000);
        var browser = limited.CreateClient();
        var userName = $"limit_acc_{Guid.NewGuid():N}";

        for (var i = 0; i < 3; i++)
        {
            (await PostLoginAsync(browser, userName, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        }

        var refused = await PostLoginAsync(browser, userName, ct);
        refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        refused.Headers.RetryAfter.Should().NotBeNull();
        (await refused.Content.ReadAsStringAsync(ct)).Should().Contain("Too many sign-in attempts");

        // Another account from the same client is not affected by this account's limit.
        (await PostLoginAsync(browser, $"limit_other_{Guid.NewGuid():N}", ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task SignInEndpoints_MoreAttemptsPerClientIpThanAllowed_AreAnswered429()
    {
        var ct = TestContext.Current.CancellationToken;
        using var limited = CreateLimitedFactory(perAccount: 1000, perClientIp: 3);
        var browser = limited.CreateClient();
        const string clientIp = "203.0.113.17";

        for (var i = 0; i < 3; i++)
        {
            (await PostLoginAsync(browser, $"limit_ip_{Guid.NewGuid():N}", ct, clientIp)).StatusCode
                .Should().Be(HttpStatusCode.OK);
        }

        (await PostLoginAsync(browser, $"limit_ip_{Guid.NewGuid():N}", ct, clientIp)).StatusCode
            .Should().Be(HttpStatusCode.TooManyRequests, "every account counts against the client's address");
        var secondFactor = new HttpRequestMessage(HttpMethod.Post, AuthApiUrl("login-2fa", SourceTenantId))
        {
            Content = JsonContent.Create(new TwoFactorLoginRequestDto { Code = "123456" })
        };
        secondFactor.Headers.Add("X-Forwarded-For", clientIp);
        (await browser.SendAsync(secondFactor, ct)).StatusCode.Should().Be(HttpStatusCode.TooManyRequests,
            "the second-factor endpoints share the client's budget");

        (await PostLoginAsync(browser, $"limit_ip_{Guid.NewGuid():N}", ct, "203.0.113.18")).StatusCode
            .Should().Be(HttpStatusCode.OK, "another client address has its own budget");
    }

    private Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> CreateLimitedFactory(int perAccount,
        int perClientIp)
        => Factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
            services.Configure<OctoIdentityServicesOptions>(o =>
            {
                o.SignInRateLimit.PermitsPerAccountPerMinute = perAccount;
                o.SignInRateLimit.PermitsPerClientIpPerMinute = perClientIp;
            })));

    private async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string userName, CancellationToken ct,
        string? clientIp = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, AuthApiUrl("login", SourceTenantId))
        {
            Content = JsonContent.Create(new LoginRequestDto { Username = userName, Password = "Wrong-Password-1" })
        };
        if (clientIp != null)
        {
            request.Headers.Add("X-Forwarded-For", clientIp);
        }

        return await client.SendAsync(request, ct);
    }

    #endregion

    #region Helpers

    private IdentityOptions GetIdentityOptions()
        => Factory.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<IdentityOptions>>().Value;

    private async Task FailOnceAsync(OctoObjectId userId)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var copy = (await userManager.FindByIdAsync(userId.ToString()))!;
        (await userManager.AccessFailedAsync(copy)).Succeeded.Should().BeTrue();
    }

    private async Task<RtUser> FindUserAsync(OctoObjectId userId)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        return (await userManager.FindByIdAsync(userId.ToString()))!;
    }

    private static async Task<LoginResultDto> PasswordLoginAsync(HttpClient browser, string tenantId, string userName,
        CancellationToken ct)
        => await LoginAsync(browser, tenantId, userName, DefaultPassword, ct);

    private static async Task<LoginResultDto> LoginAsync(HttpClient browser, string tenantId, string userName,
        string password, CancellationToken ct)
    {
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login", tenantId),
            new LoginRequestDto { Username = userName, Password = password }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!;
    }

    private async Task<Totp> EnableAuthenticatorAsync(string userName, CancellationToken ct)
    {
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;
        var setupResponse = await session.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        setupResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var setup = (await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct))!;
        var totp = new Totp(Base32Encoding.ToBytes(setup.SharedKey.Replace(" ", string.Empty).ToUpperInvariant()));
        var verify = await session.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"),
            new { Code = totp.ComputeTotp() }, ct);
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        return totp;
    }

    private static string WrongCode(Totp totp)
    {
        var valid = totp.ComputeTotp();
        return valid == "000000" ? "111111" : "000000";
    }

    private async Task<string> CreateChildTenantAsync()
    {
        var childTenantId = $"xtatom{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>()
                .SetupAsync(childTenantId);
        }

        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        using (var session = await childRepo.GetSessionAsync())
        {
            session.StartTransaction();
            await childRepo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = $"ParentTenant_{SourceTenantId}",
                DisplayName = $"Login via {SourceTenantId}",
                IsEnabled = true,
                AllowSelfRegistration = true,
                ParentTenantId = SourceTenantId
            });
            await session.CommitTransactionAsync();
        }

        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(childTenantId) != null)
            {
                return childTenantId;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{childTenantId}' did not appear in the tenant registry");
    }

    #endregion
}
