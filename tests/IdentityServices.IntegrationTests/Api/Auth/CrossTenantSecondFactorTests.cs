using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using IdentityServices.IntegrationTests.Persistence;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using OtpNet;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
///     AB#7804 / AB#7815 — every way across a tenant boundary honours the SOURCE user's second factor,
///     and the tenant switch never signs a caller in as somebody else.
/// </summary>
/// <remarks>
///     <para>
///         The source tenant A is the factory's system tenant; each test creates its own child tenant B
///         with an enabled <see cref="RtOctoTenantIdentityProvider" /> pointing to A. The entry points:
///     </para>
///     <list type="number">
///         <item>password login on B (<c>/B/api/auth/login</c>) — must answer <c>requiresTwoFactor</c> and
///             create the B session only after <c>login-2fa</c> / <c>login-recovery</c> verified a code of
///             the A user; wrong codes count against the A user's lockout;</item>
///         <item>cross-tenant token (<c>/A/api/auth/cross-tenant-token</c>) and</item>
///         <item>cross-tenant login (<c>/B/api/auth/cross-tenant-login</c>) — the A session must carry
///             second-factor evidence (<c>amr=mfa</c>) when the A user has 2FA;</item>
///         <item>tenant switch (<c>/B/api/auth/tenant-switch</c>) — the source identity is the caller's
///             own (never the request body's) and needs the same evidence;</item>
///         <item>OpenIddict token exchange — the A access token must carry <c>amr=mfa</c>.</item>
///     </list>
/// </remarks>
public class CrossTenantSecondFactorTests : IntegrationTestBase
{
    private const string AuthCodeClientId = "xt2fa-spa";
    private const string AuthCodeRedirectUri = "https://xt2fa.example/callback";
    private const string ExchangeClientId = "xt2fa-exchange";
    private const string CodeVerifier = "xt2fa-code-verifier-xt2fa-code-verifier-1234567890";

    public CrossTenantSecondFactorTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private string SourceTenantId => NormalizedSystemTenantId;

    #region 1. Password login

    [Fact]
    public async Task PasswordLogin_SourceUserWithTwoFactor_IsChallengedAndGetsNoSession()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_pwd", ct);

        var browser = CreateCookieClient();
        var login = await PasswordLoginAsync(browser, childTenantId, user.UserName, ct);

        login.Success.Should().BeFalse("the source user has 2FA enabled — no session before the second factor");
        login.RequiresTwoFactor.Should().BeTrue();
        login.CanUseTotpAuthenticator.Should().BeTrue("the source user has an authenticator");
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().NotBe(HttpStatusCode.OK,
            "a requiresTwoFactor answer must not leave an authenticated session in the child tenant");
    }

    [Fact]
    public async Task PasswordLogin_SourceUserWithTwoFactor_ValidTotp_SignsInAsShadowUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_totp", ct);

        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", childTenantId),
            new TwoFactorLoginRequestDto { Code = user.Totp.ComputeTotp() }, ct);
        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);

        result!.Success.Should().BeTrue("a valid TOTP of the SOURCE user completes the cross-tenant sign-in: {0}",
            result.ErrorMessage);
        (await GetProfileUserNameAsync(browser, childTenantId, ct)).Should().Be($"xt_{SourceTenantId}_{user.UserName}");
    }

    [Fact]
    public async Task PasswordLogin_SourceUserWithTwoFactor_ValidRecoveryCode_SignsIn()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_rec", ct);

        var codesResponse = await user.PreTwoFactorSession.PostAsync(
            ManageApiUrl("2fa/recovery-codes/generate", SourceTenantId), null, ct);
        codesResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var recoveryCode = (await codesResponse.Content.ReadFromJsonAsync<GenerateRecoveryCodesResultDto>(ct))!
            .RecoveryCodes.First();

        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("login-recovery", childTenantId),
            new RecoveryCodeLoginRequestDto { RecoveryCode = recoveryCode }, ct);
        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);

        result!.Success.Should().BeTrue("a recovery code of the SOURCE user completes the sign-in: {0}",
            result.ErrorMessage);
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().Be(HttpStatusCode.OK);

        // A recovery code is single-use — in the source tenant, where it belongs.
        var second = CreateCookieClient();
        await PasswordLoginAsync(second, childTenantId, user.UserName, ct);
        var reuse = await second.PostAsJsonAsync(AuthApiUrl("login-recovery", childTenantId),
            new RecoveryCodeLoginRequestDto { RecoveryCode = recoveryCode }, ct);
        (await reuse.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!.Success.Should().BeFalse(
            "the recovery code was redeemed in the source tenant");
    }

    [Fact]
    public async Task PasswordLogin_SourceUserWithTwoFactor_WrongCode_CountsAgainstSourceLockoutAndGetsNoSession()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_wrong", ct);
        var failedBefore = (await FindSourceUserAsync(user.UserName)).AccessFailedCount;

        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", childTenantId),
            new TwoFactorLoginRequestDto { Code = WrongCode(user.Totp) }, ct);
        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);

        result!.Success.Should().BeFalse();
        (await FindSourceUserAsync(user.UserName)).AccessFailedCount.Should().Be(failedBefore + 1,
            "a wrong second-factor code counts against the source user's lockout");
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().NotBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task PasswordLogin_AfterAPendingLocalTwoFactorChallenge_VerifiesTheSourceUsersCode()
    {
        // Review finding: the framework's two-factor cookie of an earlier LOCAL challenge in B must not win over the
        // cross-tenant challenge — the code would be checked (and counted) against the local user.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var localUserName = await CreateLocalTwoFactorUserAsync(childTenantId);
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_after_local", ct);

        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, localUserName, ct)).RequiresTwoFactor.Should().BeTrue(
            "arrangement: a local 2FA challenge is pending in B");
        (await PasswordLoginAsync(browser, childTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", childTenantId),
            new TwoFactorLoginRequestDto { Code = user.Totp.ComputeTotp() }, ct);
        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);

        result!.Success.Should().BeTrue("the code belongs to the source user of the latest challenge: {0}",
            result.ErrorMessage);
        (await GetProfileUserNameAsync(browser, childTenantId, ct)).Should().Be($"xt_{SourceTenantId}_{user.UserName}");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PasswordLogin_SourceUserWithTwoFactorButNoAuthenticator_IsRefusedWithoutSession(bool emailConfirmed)
    {
        // AB#7830: 2FA enabled, authenticator key lost (tenant clone): never a session on the password alone.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_nokey_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword, emailConfirmed: emailConfirmed,
            twoFactorEnabled: true);

        var browser = CreateCookieClient();
        var login = await PasswordLoginAsync(browser, childTenantId, userName, ct);

        login.Success.Should().BeFalse();
        login.SecondFactorSetupRequired.Should().BeTrue();
        login.RequiresTwoFactor.Should().BeFalse();
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().NotBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task PasswordLogin_SourceUserWithoutTwoFactor_SignsInDirectly()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_plain_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);

        var browser = CreateCookieClient();
        var login = await PasswordLoginAsync(browser, childTenantId, userName, ct);

        login.Success.Should().BeTrue("behaviour without 2FA is unchanged: {0}", login.ErrorMessage);
        login.RequiresTwoFactor.Should().BeFalse();
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().Be(HttpStatusCode.OK);
    }

    #endregion

    #region 2./3. Cross-tenant token + cross-tenant login

    [Fact]
    public async Task CrossTenantToken_SourceSessionWithoutSecondFactor_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        // The pre-2FA session was created with the password only (amr=pwd).
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_tok_nomfa", ct);

        var tokenResponse = await user.PreTwoFactorSession.PostAsJsonAsync(
            AuthApiUrl("cross-tenant-token", SourceTenantId),
            new CrossTenantTokenRequestDto { TargetTenantId = childTenantId }, ct);

        tokenResponse.IsSuccessStatusCode.Should().BeFalse(
            "a source session without second-factor evidence must not mint a cross-tenant token for a 2FA user");
    }

    [Fact]
    public async Task CrossTenantLogin_TokenMintedBeforeTwoFactorWasEnabled_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_tok_race_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;

        // Minted while the user had no 2FA (no evidence needed then) ...
        var token = await MintCrossTenantTokenAsync(session, childTenantId, ct);
        // ... then 2FA is enabled before the token is redeemed (within its 60 s lifetime).
        await EnableAuthenticatorAsync(session, ct);

        var browser = CreateCookieClient();
        var login = await CrossTenantLoginAsync(browser, childTenantId, token, ct);

        login.Success.Should().BeFalse(
            "the child tenant re-checks the source user's 2FA at redemption; the token carries no evidence");
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().NotBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task CrossTenantToken_SourceSessionWithSecondFactor_SignsIntoChild()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_tok_mfa", ct);
        var mfaSession = await LoginWithSecondFactorAsync(user, ct);

        var token = await MintCrossTenantTokenAsync(mfaSession, childTenantId, ct);
        var browser = CreateCookieClient();
        var login = await CrossTenantLoginAsync(browser, childTenantId, token, ct);

        login.Success.Should().BeTrue("the source session proved the second factor: {0}", login.ErrorMessage);
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task CrossTenantToken_SourceUserWithoutTwoFactor_SignsIntoChild()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_tok_plain_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;

        var token = await MintCrossTenantTokenAsync(session, childTenantId, ct);
        var browser = CreateCookieClient();
        var login = await CrossTenantLoginAsync(browser, childTenantId, token, ct);

        login.Success.Should().BeTrue("behaviour without 2FA is unchanged: {0}", login.ErrorMessage);
    }

    #endregion

    #region 4. Tenant switch (AB#7815)

    [Fact]
    public async Task TenantSwitch_CallerNamesAnotherAncestorUser_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();

        var attackerName = $"xt2fa_attacker_{Guid.NewGuid():N}";
        await CreateTestUserAsync(attackerName, password: DefaultPassword);
        // The victim deliberately has NO 2FA: the refusal must come from the identity check, not 2FA.
        var victim = await CreateTestUserAsync($"xt2fa_victim_{Guid.NewGuid():N}", password: DefaultPassword);

        var attacker = CreateCookieClient();
        (await PasswordLoginAsync(attacker, childTenantId, attackerName, ct)).Success.Should().BeTrue();

        var response = await attacker.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId, SourceUserId = victim.RtId.ToString() }, ct);
        var result = await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct);

        result!.Success.Should().BeFalse("the source identity of a tenant switch is the caller's own, never the body's");
        (await GetProfileUserNameAsync(attacker, childTenantId, ct)).Should().Be($"xt_{SourceTenantId}_{attackerName}",
            "the caller must still be signed in as themself");
    }

    [Fact]
    public async Task TenantSwitch_VictimWithTwoFactor_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();

        var attackerName = $"xt2fa_attacker2_{Guid.NewGuid():N}";
        await CreateTestUserAsync(attackerName, password: DefaultPassword);
        var victim = await CreateUserWithAuthenticatorAsync("xt2fa_victim2", ct);

        var attacker = CreateCookieClient();
        (await PasswordLoginAsync(attacker, childTenantId, attackerName, ct)).Success.Should().BeTrue();

        var response = await attacker.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId, SourceUserId = victim.Id }, ct);

        (await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct))!.Success.Should().BeFalse();
    }

    [Fact]
    public async Task TenantSwitch_OwnSourceIdentity_Succeeds()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_switch_{Guid.NewGuid():N}";
        var user = await CreateTestUserAsync(userName, password: DefaultPassword);

        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, userName, ct)).Success.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId, SourceUserId = user.RtId.ToString() }, ct);
        var result = await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct);

        result!.Success.Should().BeTrue("the caller's own source identity may switch: {0}", result.ErrorMessage);
        (await GetProfileUserNameAsync(browser, childTenantId, ct)).Should().Be($"xt_{SourceTenantId}_{userName}");
    }

    [Fact]
    public async Task TenantSwitch_OwnSourceIdentityWithTwoFactor_AfterSecondFactor_Succeeds()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_switch_mfa", ct);

        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();
        var twoFactor = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", childTenantId),
            new TwoFactorLoginRequestDto { Code = user.Totp.ComputeTotp() }, ct);
        (await twoFactor.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!.Success.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId }, ct);
        var result = await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct);

        result!.Success.Should().BeTrue("the child session carries the second-factor evidence: {0}", result.ErrorMessage);
    }

    #endregion

    #region 5. OpenIddict token exchange

    [Fact]
    public async Task TokenExchange_SubjectTokenWithoutSecondFactor_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_exch_nomfa", ct);
        await GrantChildRoleAsync(childTenantId, user);

        // Access token of the session that predates 2FA: amr=pwd.
        var subjectToken = await GetAccessTokenAsync(user.PreTwoFactorSession, ct);
        var (status, body) = await ExchangeAsync(subjectToken, childTenantId, ct);

        status.Should().NotBe(HttpStatusCode.OK, "no target-tenant token without second-factor evidence (error: {0})", ErrorOf(body));
        body.Should().Contain("second_factor_required");
    }

    [Fact]
    public async Task TokenExchange_SubjectTokenWithSecondFactor_IssuesTokenThatKeepsTheEvidence()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_exch_mfa", ct);
        await GrantChildRoleAsync(childTenantId, user);

        var subjectToken = await GetAccessTokenAsync(await LoginWithSecondFactorAsync(user, ct), ct);
        AmrOf(subjectToken).Should().Contain("mfa", "a 2FA sign-in stamps amr=mfa into the access token");

        var (status, body) = await ExchangeAsync(subjectToken, childTenantId, ct);

        status.Should().Be(HttpStatusCode.OK, "the subject token proves the second factor (error: {0})", ErrorOf(body));
        var exchanged = JsonNode.Parse(body)!["access_token"]!.GetValue<string>();
        AmrOf(exchanged).Should().Contain("mfa", "the evidence travels with the exchanged token (chained exchanges)");
    }

    [Fact]
    public async Task TokenExchange_SourceUserWithoutTwoFactor_IssuesToken()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_exch_plain_{Guid.NewGuid():N}";
        var rtUser = await CreateTestUserAsync(userName, password: DefaultPassword);
        await GrantChildRoleAsync(childTenantId, rtUser.RtId.ToString(), userName);
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;

        var (status, body) = await ExchangeAsync(await GetAccessTokenAsync(session, ct), childTenantId, ct);

        status.Should().Be(HttpStatusCode.OK, "behaviour without 2FA is unchanged (error: {0})", ErrorOf(body));
    }

    #endregion

    #region 6. Locked-out or disabled source user (AB#7855)

    [Fact]
    public async Task LockedOutSourceUser_WithAValidMfaSession_CrossesNoBoundary()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_locked", ct);
        await GrantChildRoleAsync(childTenantId, user);
        var mfaSession = await LoginWithSecondFactorAsync(user, ct);
        var subjectToken = await GetAccessTokenAsync(mfaSession, ct);
        var tokenMintedBeforeTheLock = await MintCrossTenantTokenAsync(mfaSession, childTenantId, ct);

        await SetSourceUserLockoutAsync(user.UserName, DateTimeOffset.UtcNow.AddHours(1));

        var crossTenantToken = await mfaSession.PostAsJsonAsync(AuthApiUrl("cross-tenant-token", SourceTenantId),
            new CrossTenantTokenRequestDto { TargetTenantId = childTenantId }, ct);
        crossTenantToken.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "a locked-out user gets no cross-tenant token, whatever session it still holds");

        var browser = CreateCookieClient();
        (await CrossTenantLoginAsync(browser, childTenantId, tokenMintedBeforeTheLock, ct)).Success.Should().BeFalse(
            "a token minted before the lock is refused at redemption");
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().NotBe(HttpStatusCode.OK);

        var (status, body) = await ExchangeAsync(subjectToken, childTenantId, ct);
        status.Should().NotBe(HttpStatusCode.OK,
            "an access token of a locked-out user is not exchanged into another tenant (error: {0})", ErrorOf(body));
    }

    [Fact]
    public async Task LockedOutSourceUser_TenantSwitchFromAChildSession_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_locked_switch_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, userName, ct)).Success.Should().BeTrue();

        await SetSourceUserLockoutAsync(userName, DateTimeOffset.UtcNow.AddHours(1));

        var response = await browser.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId }, ct);
        var result = await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct);

        result!.Success.Should().BeFalse("the source user is locked out");
    }

    [Fact]
    public async Task DisabledSourceUser_WithAValidSession_CrossesNoBoundary()
    {
        // "Disabled" = the sign-in rules refuse the user (SignInManager.CanSignInAsync, as on the token endpoint);
        // here an e-mail that is no longer confirmed while confirmed e-mails are required.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var userName = $"xt2fa_disabled_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;

        var signIn = Factory.Services.GetRequiredService<IOptions<IdentityOptions>>().Value.SignIn;
        try
        {
            signIn.RequireConfirmedEmail = true;
            using (var scope = CreateScope())
            {
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
                var stored = (await userManager.FindByNameAsync(userName))!;
                stored.EmailConfirmed = false;
                (await userManager.UpdateAsync(stored)).Succeeded.Should().BeTrue();
            }

            var crossTenantToken = await session.PostAsJsonAsync(AuthApiUrl("cross-tenant-token", SourceTenantId),
                new CrossTenantTokenRequestDto { TargetTenantId = childTenantId }, ct);
            crossTenantToken.StatusCode.Should().Be(HttpStatusCode.Forbidden,
                "a user the sign-in rules refuse gets no cross-tenant token");
        }
        finally
        {
            signIn.RequireConfirmedEmail = false;
        }
    }

    private async Task SetSourceUserLockoutAsync(string userName, DateTimeOffset lockoutEnd)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var stored = (await userManager.FindByNameAsync(userName))!;
        (await userManager.SetLockoutEnabledAsync(stored, true)).Succeeded.Should().BeTrue();
        (await userManager.SetLockoutEndDateAsync(stored, lockoutEnd)).Succeeded.Should().BeTrue();
    }

    #endregion

    #region Helpers

    private sealed record TwoFactorUser(string Id, string UserName, Totp Totp, HttpClient PreTwoFactorSession);

    private async Task<LoginResultDto> PasswordLoginAsync(HttpClient browser, string tenantId, string userName,
        CancellationToken ct)
    {
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login", tenantId),
            new LoginRequestDto { Username = userName, Password = DefaultPassword }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!;
    }

    private async Task<string> MintCrossTenantTokenAsync(HttpClient sourceSession, string childTenantId,
        CancellationToken ct)
    {
        var response = await sourceSession.PostAsJsonAsync(AuthApiUrl("cross-tenant-token", SourceTenantId),
            new CrossTenantTokenRequestDto { TargetTenantId = childTenantId }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "cross-tenant token: {0}",
            await response.Content.ReadAsStringAsync(ct));
        return (await response.Content.ReadFromJsonAsync<CrossTenantTokenResultDto>(ct))!.Token;
    }

    private async Task<LoginResultDto> CrossTenantLoginAsync(HttpClient browser, string childTenantId, string token,
        CancellationToken ct)
    {
        var response = await browser.PostAsJsonAsync(AuthApiUrl("cross-tenant-login", childTenantId),
            new CrossTenantLoginRequestDto { Token = token }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!;
    }

    private static async Task<HttpStatusCode> GetProfileStatusAsync(HttpClient browser, string tenantId,
        CancellationToken ct)
        => (await browser.GetAsync(ManageApiUrl("profile", tenantId), ct)).StatusCode;

    private static async Task<string?> GetProfileUserNameAsync(HttpClient browser, string tenantId, CancellationToken ct)
    {
        var response = await browser.GetAsync(ManageApiUrl("profile", tenantId), ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!["userName"]?.GetValue<string>();
    }

    /// <summary>
    ///     A source-tenant user with an enrolled authenticator. <see cref="TwoFactorUser.PreTwoFactorSession" />
    ///     is the password-only session that enrolled it — a session without second-factor evidence.
    /// </summary>
    private async Task<TwoFactorUser> CreateUserWithAuthenticatorAsync(string prefix, CancellationToken ct)
    {
        var userName = $"{prefix}_{Guid.NewGuid():N}";
        var user = await CreateTestUserAsync(userName, password: DefaultPassword);
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;
        var totp = await EnableAuthenticatorAsync(session, ct);
        return new TwoFactorUser(user.RtId.ToString(), userName, totp, session);
    }

    private static async Task<Totp> EnableAuthenticatorAsync(HttpClient session, CancellationToken ct)
    {
        var setupResponse = await session.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        setupResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var setup = (await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct))!;
        var totp = new Totp(Base32Encoding.ToBytes(setup.SharedKey.Replace(" ", string.Empty).ToUpperInvariant()));
        var verify = await session.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"),
            new { Code = totp.ComputeTotp() }, ct);
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        return totp;
    }

    /// <summary>A source-tenant session created with password + TOTP (amr=mfa).</summary>
    private async Task<HttpClient> LoginWithSecondFactorAsync(TwoFactorUser user, CancellationToken ct)
    {
        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, SourceTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", SourceTenantId),
            new TwoFactorLoginRequestDto { Code = user.Totp.ComputeTotp() }, ct);
        (await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!.Success.Should().BeTrue();
        return browser;
    }

    /// <summary>A user that lives in the child tenant itself, with an authenticator and 2FA enabled.</summary>
    private async Task<string> CreateLocalTwoFactorUserAsync(string childTenantId)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        using var scope = CreateScope();
        var sp = scope.ServiceProvider;
        using var userManager = new UserManager<RtUser>(
            new OctoUserStore(new FixedTenantResolver(childRepo), sp.GetRequiredService<IGroupRoleResolver>(), null),
            sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<IdentityOptions>>(),
            sp.GetRequiredService<IPasswordHasher<RtUser>>(),
            sp.GetServices<IUserValidator<RtUser>>(),
            sp.GetServices<IPasswordValidator<RtUser>>(),
            sp.GetRequiredService<ILookupNormalizer>(),
            sp.GetRequiredService<IdentityErrorDescriber>(),
            sp,
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<UserManager<RtUser>>>());

        var userName = $"xt2fa_local_{Guid.NewGuid():N}";
        var user = new RtUserBuilder().WithUserName(userName).WithEmail($"{userName}@example.com")
            .WithEmailConfirmed(true).Build();
        (await userManager.CreateAsync(user, DefaultPassword)).Succeeded.Should().BeTrue();
        (await userManager.ResetAuthenticatorKeyAsync(user)).Succeeded.Should().BeTrue();
        (await userManager.SetTwoFactorEnabledAsync(user, true)).Succeeded.Should().BeTrue();
        return userName;
    }

    private static string WrongCode(Totp totp)
    {
        var valid = totp.ComputeTotp();
        return valid == "000000" ? "111111" : "000000";
    }

    private async Task<RtUser> FindSourceUserAsync(string userName)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        return (await userManager.FindByNameAsync(userName))!;
    }

    private async Task<string> CreateChildTenantAsync()
    {
        var childTenantId = $"xt2fa{Guid.NewGuid():N}"[..20];
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

        await WaitUntilRegistryKnowsAsync(childTenantId);
        return childTenantId;
    }

    /// <summary>
    ///     The cross-tenant services read tenants through the cached <see cref="ITenantRegistry" />, which re-reads
    ///     an unknown id at most every <see cref="TenantRegistry.MissRefreshInterval" />. A tenant created a moment
    ///     ago is therefore invisible for up to that long — in production tenants exist long before anybody signs
    ///     into them, here the arrangement waits instead of letting the first assertion race the cache.
    /// </summary>
    private async Task WaitUntilRegistryKnowsAsync(string tenantId)
    {
        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    private Task GrantChildRoleAsync(string childTenantId, TwoFactorUser user)
        => GrantChildRoleAsync(childTenantId, user.Id, user.UserName);

    /// <summary>Explicit provisioning in B (a mapping with a role) — the token exchange refuses role-less users.</summary>
    private async Task GrantChildRoleAsync(string childTenantId, string sourceUserId, string sourceUserName)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var roleName = $"xt2farole{Guid.NewGuid():N}"[..20];
        var roleId = OctoObjectId.GenerateNewId();

        using var session = await childRepo.GetSessionAsync();
        session.StartTransaction();
        await childRepo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = roleId,
            Name = roleName,
            NormalizedName = roleName.ToUpperInvariant()
        });
        await childRepo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = SourceTenantId,
            SourceUserId = sourceUserId,
            SourceUserName = sourceUserName,
            MappedRoleIds = new AttributeStringValueList { roleId.ToString() }
        });
        await session.CommitTransactionAsync();

        // The exchanging public client must exist in the target tenant (clients are per tenant).
        var clientStore = new ClientStore(new FixedTenantResolver(childRepo));
        if (await clientStore.FindRtClientByIdAsync(ExchangeClientId) == null)
        {
            await clientStore.CreateAsync(new RtClientBuilder()
                .WithClientId(ExchangeClientId)
                .WithClientName(ExchangeClientId)
                .WithGrantTypes("urn:ietf:params:oauth:grant-type:token-exchange")
                .WithScopes("openid")
                .RequirePkce(false)
                .Build());
        }
    }

    /// <summary>Authorization code + PKCE in the source tenant, driven by the given browser session.</summary>
    private async Task<string> GetAccessTokenAsync(HttpClient browser, CancellationToken ct)
    {
        using (var scope = CreateScope())
        {
            var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
            if (await clientStore.FindRtClientByIdAsync(AuthCodeClientId) == null)
            {
                await clientStore.CreateAsync(new RtClientBuilder()
                    .WithClientId(AuthCodeClientId)
                    .WithClientName(AuthCodeClientId)
                    .WithGrantTypes("authorization_code")
                    .WithScopes("openid", "profile")
                    .WithRedirectUris(AuthCodeRedirectUri)
                    .RequirePkce()
                    .Build());
            }
        }

        var codeChallenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(CodeVerifier)));
        var authorizeUrl = "/connect/authorize" +
                           $"?client_id={AuthCodeClientId}" +
                           $"&redirect_uri={Uri.EscapeDataString(AuthCodeRedirectUri)}" +
                           "&response_type=code" +
                           $"&scope={Uri.EscapeDataString("openid profile")}" +
                           "&state=xt2fa-state&nonce=xt2fa-nonce" +
                           $"&code_challenge={codeChallenge}&code_challenge_method=S256" +
                           $"&acr_values={Uri.EscapeDataString($"tenant:{SourceTenantId}")}";

        var authorize = await browser.GetAsync(authorizeUrl, ct);
        ((int)authorize.StatusCode).Should().BeInRange(302, 303, "authorize: {0}",
            await authorize.Content.ReadAsStringAsync(ct));
        var code = HttpUtility.ParseQueryString(authorize.Headers.Location!.Query)["code"];
        code.Should().NotBeNullOrEmpty("authorize must redirect with a code: {0}", authorize.Headers.Location);

        var tokenResponse = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = AuthCodeClientId,
                ["code"] = code!,
                ["redirect_uri"] = AuthCodeRedirectUri,
                ["code_verifier"] = CodeVerifier
            }), ct);
        var raw = await tokenResponse.Content.ReadAsStringAsync(ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK, "code redemption: {0}", raw);
        return JsonNode.Parse(raw)!["access_token"]!.GetValue<string>();
    }

    private async Task<(HttpStatusCode Status, string Body)> ExchangeAsync(string subjectToken, string childTenantId,
        CancellationToken ct)
    {
        var response = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
                ["client_id"] = ExchangeClientId,
                ["subject_token"] = subjectToken,
                ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
                ["acr_values"] = $"tenant:{childTenantId}"
            }), ct);
        return (response.StatusCode, await response.Content.ReadAsStringAsync(ct));
    }

    /// <summary>The OAuth error of a token response — never the response itself, which may carry a token.</summary>
    private static string ErrorOf(string body)
    {
        try
        {
            var node = JsonNode.Parse(body);
            return $"{node?["error"]?.GetValue<string>() ?? "(none)"}: {node?["error_description"]?.GetValue<string>()}";
        }
        catch (System.Text.Json.JsonException)
        {
            return "(no JSON body)";
        }
    }

    private static IReadOnlyList<string> AmrOf(string jwt)
        => new JsonWebToken(jwt).Claims.Where(c => c.Type == "amr").Select(c => c.Value).ToList();

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    #endregion
}
