using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using Microsoft.AspNetCore.DataProtection;
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

    #region 6. Hardening (AB#7861)

    private const string ChallengeCookieName = ".AspNetCore.Octo.CrossTenantTwoFactor";

    [Fact]
    public async Task Challenge_ReplayedAfterSuccess_IsVoid()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_replay", ct);

        var browser = CreateCookieClient();
        var challenge = await PasswordLoginCapturingChallengeAsync(browser, childTenantId, user.UserName, ct);
        (await LoginTwoFactorAsync(browser, childTenantId, user.Totp.ComputeTotp(), ct)).Success.Should().BeTrue();

        var replay = await LoginTwoFactorWithChallengeAsync(childTenantId, challenge, user.Totp.ComputeTotp(), ct);
        replay.Success.Should().BeFalse("a completed challenge is single-use, also as a copy");
        replay.ErrorMessage.Should().Contain("session expired");
    }

    [Fact]
    public async Task Challenge_AfterLogout_IsVoid()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_logout", ct);

        var browser = CreateCookieClient();
        var challenge = await PasswordLoginCapturingChallengeAsync(browser, childTenantId, user.UserName, ct);
        var logout = await browser.PostAsJsonAsync(AuthApiUrl("logout", childTenantId), new LogoutRequestDto(), ct);
        logout.StatusCode.Should().Be(HttpStatusCode.OK);
        logout.Headers.TryGetValues("Set-Cookie", out var cleared).Should().BeTrue();
        cleared!.Should().Contain(c => c.StartsWith(ChallengeCookieName + "=;", StringComparison.Ordinal),
            "the logout deletes the pending challenge in the browser");

        var replay = await LoginTwoFactorWithChallengeAsync(childTenantId, challenge, user.Totp.ComputeTotp(), ct);
        replay.Success.Should().BeFalse("the logout voided the challenge itself, not only the browser's copy");
    }

    [Fact]
    public async Task Challenge_ForAnotherTenant_IsIgnored()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var otherChildTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_wrongtenant", ct);

        var challenge = await PasswordLoginCapturingChallengeAsync(CreateCookieClient(), childTenantId, user.UserName, ct);

        var result = await LoginTwoFactorWithChallengeAsync(otherChildTenantId, challenge, user.Totp.ComputeTotp(), ct);
        result.Success.Should().BeFalse("the challenge was issued for another tenant");
        result.ErrorMessage.Should().Contain("session expired");
    }

    [Fact]
    public async Task Challenge_Tampered_IsIgnored()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_tamper", ct);

        var challenge = await PasswordLoginCapturingChallengeAsync(CreateCookieClient(), childTenantId, user.UserName, ct);
        var tampered = challenge[..^4] + (challenge.EndsWith("AAAA", StringComparison.Ordinal) ? "BBBB" : "AAAA");

        var result = await LoginTwoFactorWithChallengeAsync(childTenantId, tampered, user.Totp.ComputeTotp(), ct);
        result.Success.Should().BeFalse("a challenge that fails data protection is ignored");
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Challenge_ExpiredOrWithoutNonce_IsIgnored(bool expired, bool withoutNonce)
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_forged", ct);

        // A challenge protected with the service's own key ring (as the server would issue it), but expired or
        // in the pre-AB#7861 shape without a nonce.
        var protector = Factory.Services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>()
            .CreateProtector("CrossTenantTwoFactorChallenge").ToTimeLimitedDataProtector();
        var payload = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["SourceTenantId"] = SourceTenantId,
            ["SourceUserId"] = user.Id,
            ["TargetTenantId"] = childTenantId,
            ["RememberLogin"] = false,
            ["Nonce"] = withoutNonce ? string.Empty : Guid.NewGuid().ToString("N")
        });
        var challenge = protector.Protect(payload, expired ? TimeSpan.FromSeconds(-1) : TimeSpan.FromMinutes(5));

        var result = await LoginTwoFactorWithChallengeAsync(childTenantId, challenge, user.Totp.ComputeTotp(), ct);
        result.Success.Should().BeFalse(expired ? "the challenge has expired" : "a challenge without a nonce is void");
    }

    [Fact]
    public async Task EmailCodePath_SendsAndVerifiesTheSourceUsersCode()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_email", ct);

        var browser = CreateCookieClient();
        var login = await PasswordLoginAsync(browser, childTenantId, user.UserName, ct);
        login.CanUseEmailCode.Should().BeTrue("the source user has a confirmed e-mail");

        var send = await browser.PostAsync(AuthApiUrl("send-2fa-email", childTenantId), null, ct);
        (await send.Content.ReadFromJsonAsync<SendTwoFactorEmailResultDto>(ct))!.Success.Should().BeTrue();

        var failedBefore = (await FindSourceUserAsync(user.UserName)).AccessFailedCount;
        var wrong = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa-email", childTenantId),
            new TwoFactorEmailLoginRequestDto { Code = "000000" }, ct);
        (await wrong.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!.Success.Should().BeFalse();
        (await FindSourceUserAsync(user.UserName)).AccessFailedCount.Should().Be(failedBefore + 1,
            "a wrong e-mail code counts against the source user");

        string code;
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            code = await userManager.GenerateTwoFactorTokenAsync((await userManager.FindByNameAsync(user.UserName))!,
                TokenOptions.DefaultEmailProvider);
        }

        var valid = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa-email", childTenantId),
            new TwoFactorEmailLoginRequestDto { Code = code }, ct);
        var result = (await valid.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!;
        result.Success.Should().BeTrue("a valid e-mail code of the SOURCE user completes the sign-in: {0}",
            result.ErrorMessage);
        (await GetProfileStatusAsync(browser, childTenantId, ct)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task SelfRegistrationDenied_SourceUserWithTwoFactor_IsRefusedBeforeAnyChallenge()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync(allowSelfRegistration: false);
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_noselfreg", ct);

        var browser = CreateCookieClient();
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login", childTenantId),
            new LoginRequestDto { Username = user.UserName, Password = DefaultPassword }, ct);
        var login = (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!;

        login.Success.Should().BeFalse();
        login.RequiresTwoFactor.Should().BeFalse("a user who may not enter this tenant is not asked for a code");
        response.Headers.TryGetValues("Set-Cookie", out var cookies);
        (cookies ?? []).Should().NotContain(c => c.StartsWith(ChallengeCookieName + "=", StringComparison.Ordinal) &&
                                                  !c.StartsWith(ChallengeCookieName + "=;", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TenantSwitch_LocalCallerWithoutSourceUserId_IsRefused()
    {
        // A user that lives in the child tenant itself has no identity in the parent; omitting SourceUserId must not
        // make the server pick one.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var localUserName = await CreateLocalUserAsync(childTenantId);
        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, localUserName, ct)).Success.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId }, ct);
        var result = await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct);

        result!.Success.Should().BeFalse("a local user has no source identity in the parent tenant");
    }

    [Fact]
    public async Task StoredAmrClaim_IsNoSecondFactorEvidence()
    {
        // Review finding 9: anything that can write RtUser.Claims must not be able to mint amr=mfa.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_storedamr", ct);
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var stored = (await userManager.FindByNameAsync(user.UserName))!;
            (await userManager.AddClaimAsync(stored, SecondFactorEvidence.CreateClaim())).Succeeded.Should().BeTrue();
        }

        // The password-only session (amr=pwd) is rebuilt from the store: change-password re-signs the user in
        // (RefreshSignInAsync -> CreateUserPrincipalAsync -> store claims), as the 30-minute revalidation does.
        var change = await user.PreTwoFactorSession.PostAsJsonAsync(ManageApiUrl("change-password"),
            new ChangePasswordRequestDto
            {
                CurrentPassword = DefaultPassword, NewPassword = "Changed123!", ConfirmPassword = "Changed123!"
            }, ct);
        change.StatusCode.Should().Be(HttpStatusCode.OK, await change.Content.ReadAsStringAsync(ct));

        var token = await GetAccessTokenAsync(user.PreTwoFactorSession, ct);
        AmrOf(token).Should().NotContain("mfa", "a stored claim is not evidence of a second factor");
        var crossTenantToken = await user.PreTwoFactorSession.PostAsJsonAsync(
            AuthApiUrl("cross-tenant-token", SourceTenantId),
            new CrossTenantTokenRequestDto { TargetTenantId = childTenantId }, ct);
        crossTenantToken.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task GrandchildHop_ShadowSessionWhoseHomeUserHasTwoFactor_NeedsEvidence()
    {
        // B is a child of A, C a child of B. The A user signs into B without 2FA (no evidence), then enables 2FA.
        // The B session (shadow xt_A_user) must not carry the user on into C without a second factor.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var grandchildTenantId = await CreateChildTenantAsync(parentTenantId: childTenantId);
        var userName = $"xt2fa_hop_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);

        var childSession = CreateCookieClient();
        (await PasswordLoginAsync(childSession, childTenantId, userName, ct)).Success.Should().BeTrue();
        var homeSession = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;
        await EnableAuthenticatorAsync(homeSession, ct);

        var hop = await childSession.PostAsJsonAsync(AuthApiUrl("cross-tenant-token", childTenantId),
            new CrossTenantTokenRequestDto { TargetTenantId = grandchildTenantId }, ct);
        hop.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "the home user's second factor counts for every hop of its shadow chain");
    }

    [Fact]
    public async Task GrandchildHop_ShadowSessionWithEvidence_SignsIntoGrandchild()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var grandchildTenantId = await CreateChildTenantAsync(parentTenantId: childTenantId);
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_hopmfa", ct);

        var childSession = CreateCookieClient();
        (await PasswordLoginAsync(childSession, childTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();
        (await LoginTwoFactorAsync(childSession, childTenantId, user.Totp.ComputeTotp(), ct)).Success.Should().BeTrue();

        var token = await MintCrossTenantTokenAsync(childSession, childTenantId, grandchildTenantId, ct);
        var browser = CreateCookieClient();
        var login = await CrossTenantLoginAsync(browser, grandchildTenantId, token, ct);

        login.Success.Should().BeTrue("the B session carries the evidence on to C: {0}", login.ErrorMessage);
        (await GetProfileUserNameAsync(browser, grandchildTenantId, ct)).Should()
            .Be($"xt_{childTenantId}_xt_{SourceTenantId}_{user.UserName}");
    }

    [Fact]
    public async Task DeviceApproval_ShadowSessionWithEvidence_IssuesADeviceTokenThatKeepsAmrMfa()
    {
        // AB#7884: the device approval passes the session's amr on, so a 2FA user's device token can be exchanged further.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync();
        var user = await CreateUserWithAuthenticatorAsync("xt2fa_device", ct);

        var childSession = CreateCookieClient();
        (await PasswordLoginAsync(childSession, childTenantId, user.UserName, ct)).RequiresTwoFactor.Should().BeTrue();
        (await LoginTwoFactorAsync(childSession, childTenantId, user.Totp.ComputeTotp(), ct)).Success.Should().BeTrue();

        var (userCode, deviceCode) = await StartDeviceFlowAsync(childTenantId, ct);
        var approve = await childSession.PostAsync("/connect/deviceverification",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["user_code"] = userCode }), ct);
        var approveBody = JsonNode.Parse(await approve.Content.ReadAsStringAsync(ct))!;
        approveBody["success"]!.GetValue<bool>().Should().BeTrue("the shadow user exists in the child tenant: {0}",
            approveBody["errorMessage"]?.GetValue<string>());

        var accessToken = await RedeemDeviceCodeAsync(childTenantId, deviceCode, ct);
        AmrOf(accessToken).Should().Contain("mfa", "the device token carries the session's second-factor evidence");
    }

    [Fact]
    public async Task DeviceApproval_SessionWhoseSubjectNoLongerExists_IsDenied()
    {
        // AB#7884: no cross-tenant provisioning on the device endpoint; a session whose subject is not a user of the
        // request tenant (here: deleted after sign-in) is refused with access_denied.
        var ct = TestContext.Current.CancellationToken;
        var userName = $"xt2fa_device_gone_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var session = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;
        var (userCode, _) = await StartDeviceFlowAsync(SourceTenantId, ct);
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            (await userManager.DeleteAsync((await userManager.FindByNameAsync(userName))!)).Succeeded.Should().BeTrue();
        }

        var approve = await session.PostAsync("/connect/deviceverification",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["user_code"] = userCode }), ct);

        approve.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = JsonNode.Parse(await approve.Content.ReadAsStringAsync(ct))!;
        body["success"]!.GetValue<bool>().Should().BeFalse();
        body["error"]!.GetValue<string>().Should().Be("access_denied");
    }

    private const string DeviceClientId = "xt2fa-device";

    private async Task<(string UserCode, string DeviceCode)> StartDeviceFlowAsync(string tenantId, CancellationToken ct)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var repo = string.Equals(tenantId, SourceTenantId, StringComparison.OrdinalIgnoreCase)
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
        var clientStore = new ClientStore(new FixedTenantResolver(repo));
        if (await clientStore.FindRtClientByIdAsync(DeviceClientId) == null)
        {
            await clientStore.CreateAsync(new RtClientBuilder()
                .WithClientId(DeviceClientId)
                .WithClientName(DeviceClientId)
                .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
                .WithScopes("openid")
                .RequirePkce(false)
                .Build());
        }

        var response = await CreateAnonymousClient().PostAsync("/connect/deviceauthorization",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = DeviceClientId,
                ["scope"] = "openid",
                ["acr_values"] = $"tenant:{tenantId}"
            }), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, raw);
        var json = JsonNode.Parse(raw)!;
        return (json["user_code"]!.GetValue<string>(), json["device_code"]!.GetValue<string>());
    }

    private async Task<string> RedeemDeviceCodeAsync(string tenantId, string deviceCode, CancellationToken ct)
    {
        var response = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["client_id"] = DeviceClientId,
                ["device_code"] = deviceCode,
                ["acr_values"] = $"tenant:{tenantId}"
            }), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "device code redemption: {0}", ErrorOf(raw));
        return JsonNode.Parse(raw)!["access_token"]!.GetValue<string>();
    }

    private async Task<string> PasswordLoginCapturingChallengeAsync(HttpClient browser, string tenantId,
        string userName, CancellationToken ct)
    {
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login", tenantId),
            new LoginRequestDto { Username = userName, Password = DefaultPassword }, ct);
        (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!.RequiresTwoFactor.Should().BeTrue();
        response.Headers.TryGetValues("Set-Cookie", out var cookies).Should().BeTrue();
        var header = cookies!.Single(c => c.StartsWith(ChallengeCookieName + "=", StringComparison.Ordinal));
        return header[(ChallengeCookieName.Length + 1)..header.IndexOf(';')];
    }

    private static async Task<TwoFactorLoginResultDto> LoginTwoFactorAsync(HttpClient browser, string tenantId,
        string code, CancellationToken ct)
    {
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login-2fa", tenantId),
            new TwoFactorLoginRequestDto { Code = code }, ct);
        return (await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!;
    }

    /// <summary>A fresh client that presents only the given challenge cookie value (a copy of it).</summary>
    private async Task<TwoFactorLoginResultDto> LoginTwoFactorWithChallengeAsync(string tenantId, string challenge,
        string code, CancellationToken ct)
    {
        var client = Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = false,
            AllowAutoRedirect = false
        });
        var request = new HttpRequestMessage(HttpMethod.Post, AuthApiUrl("login-2fa", tenantId))
        {
            Content = JsonContent.Create(new TwoFactorLoginRequestDto { Code = code })
        };
        request.Headers.Add("Cookie", $"{ChallengeCookieName}={challenge}");
        var response = await client.SendAsync(request, ct);
        return (await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct))!;
    }

    private async Task<string> MintCrossTenantTokenAsync(HttpClient session, string fromTenantId, string toTenantId,
        CancellationToken ct)
    {
        var response = await session.PostAsJsonAsync(AuthApiUrl("cross-tenant-token", fromTenantId),
            new CrossTenantTokenRequestDto { TargetTenantId = toTenantId }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "cross-tenant token: {0}",
            await response.Content.ReadAsStringAsync(ct));
        return (await response.Content.ReadFromJsonAsync<CrossTenantTokenResultDto>(ct))!.Token;
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
    private Task<string> CreateLocalTwoFactorUserAsync(string childTenantId)
        => CreateLocalUserAsync(childTenantId, twoFactor: true);

    /// <summary>A user that lives in the child tenant itself (optionally with an authenticator and 2FA).</summary>
    private async Task<string> CreateLocalUserAsync(string childTenantId, bool twoFactor = false)
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
        if (twoFactor)
        {
            (await userManager.ResetAuthenticatorKeyAsync(user)).Succeeded.Should().BeTrue();
            (await userManager.SetTwoFactorEnabledAsync(user, true)).Succeeded.Should().BeTrue();
        }

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

    private async Task<string> CreateChildTenantAsync(string? parentTenantId = null, bool allowSelfRegistration = true)
    {
        parentTenantId ??= SourceTenantId;
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
                Name = $"ParentTenant_{parentTenantId}",
                DisplayName = $"Login via {parentTenantId}",
                IsEnabled = true,
                AllowSelfRegistration = allowSelfRegistration,
                ParentTenantId = parentTenantId
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
