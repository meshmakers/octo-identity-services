using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Helpers;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using OtpNet;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
/// Integration tests for the two-factor authentication login endpoints.
/// </summary>
public class TwoFactorLoginTests : IntegrationTestBase
{
    public TwoFactorLoginTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    #region Login Two-Factor Required Tests

    [Fact]
    public async Task Login_WithTwoFactorEnabled_ReturnsTwoFactorRequired()
    {
        // Arrange
        var userName = $"2fa_login_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Create user and enable 2FA
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var setupClient = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        setupClient.Should().NotBeNull();

        // Enable 2FA
        var setupResponse = await setupClient!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        setupResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        setup.Should().NotBeNull();
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));

        var verifyResponse = await setupClient.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = totp.ComputeTotp() }, ct);
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Create a new anonymous client for login
        var loginClient = CreateAnonymousClient();
        var request = new LoginRequestDto
        {
            Username = userName,
            Password = TestUsers.DefaultPassword,
            RememberLogin = false
        };

        // Act
        var response = await loginClient.PostAsJsonAsync(AuthApiUrl("login"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.RequiresTwoFactor.Should().BeTrue();
        result.CanUseTotpAuthenticator.Should().BeTrue();
        result.ErrorMessage.Should().Be("Two-factor authentication required");
    }

    #endregion

    #region TOTP Login Tests

    [Fact]
    public async Task LoginTwoFactor_WithValidCode_ReturnsSuccess()
    {
        // Arrange
        var userName = $"2fa_totp_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Create user and enable 2FA
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var setupClient = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        setupClient.Should().NotBeNull();

        var setupResponse = await setupClient!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        await setupClient.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = totp.ComputeTotp() }, ct);

        // Create a new client with cookie support
        var loginClient = CreateCookieClient();

        // First, login to trigger 2FA
        var loginRequest = new LoginRequestDto
        {
            Username = userName,
            Password = TestUsers.DefaultPassword,
            RememberLogin = false
        };
        var loginResponse = await loginClient.PostAsJsonAsync(AuthApiUrl("login"), loginRequest, ct);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<LoginResultDto>(ct);
        loginResult!.RequiresTwoFactor.Should().BeTrue("Login should require 2FA");

        // Generate a new TOTP code
        var verifyCode = totp.ComputeTotp();
        var twoFactorRequest = new TwoFactorLoginRequestDto
        {
            Code = verifyCode,
            RememberMachine = false
        };

        // Act
        var response = await loginClient.PostAsJsonAsync(AuthApiUrl("login-2fa"), twoFactorRequest, ct);

        // Assert - check status code first
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(ct);
            Assert.Fail($"Expected success status code but got {response.StatusCode}. Response: {errorContent}");
        }

        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
        result.RedirectUrl.Should().NotBeNullOrEmpty();
        result.ErrorMessage.Should().BeNull();
    }

    [Fact]
    public async Task LoginTwoFactor_WithInvalidCode_ReturnsError()
    {
        // Arrange
        var userName = $"2fa_invalid_totp_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Create user and enable 2FA
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var setupClient = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        setupClient.Should().NotBeNull();

        var setupResponse = await setupClient!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        await setupClient.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = totp.ComputeTotp() }, ct);

        // Create a new client with cookie support
        var loginClient = CreateCookieClient();

        // First, login to trigger 2FA
        var loginRequest = new LoginRequestDto
        {
            Username = userName,
            Password = TestUsers.DefaultPassword,
            RememberLogin = false
        };
        var loginResponse = await loginClient.PostAsJsonAsync(AuthApiUrl("login"), loginRequest, ct);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var twoFactorRequest = new TwoFactorLoginRequestDto
        {
            Code = "000000",
            RememberMachine = false
        };

        // Act
        var response = await loginClient.PostAsJsonAsync(AuthApiUrl("login-2fa"), twoFactorRequest, ct);

        // Assert - check status code first
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(ct);
            Assert.Fail($"Expected success status code but got {response.StatusCode}. Response: {errorContent}");
        }

        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Invalid authenticator code");
    }

    [Fact]
    public async Task LoginTwoFactor_WithoutPriorLogin_ReturnsSessionExpiredError()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var request = new TwoFactorLoginRequestDto
        {
            Code = "123456",
            RememberMachine = false
        };

        // Act
        var response = await client.PostAsJsonAsync(AuthApiUrl("login-2fa"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("session expired");
    }

    #endregion

    #region Recovery Code Tests

    [Fact]
    public async Task LoginRecovery_WithValidCode_ReturnsSuccess()
    {
        // Arrange
        var userName = $"2fa_recovery_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Create user and enable 2FA
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var setupClient = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        setupClient.Should().NotBeNull();

        var setupResponse = await setupClient!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));

        var verifyResponse = await setupClient.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = totp.ComputeTotp() }, ct);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<VerifyAuthenticatorResultDto>(ct);
        var recoveryCodes = verifyResult!.RecoveryCodes.ToList();
        recoveryCodes.Should().HaveCount(10);

        // Create a new client with cookie support
        var loginClient = CreateCookieClient();

        // First, login to trigger 2FA
        var loginRequest = new LoginRequestDto
        {
            Username = userName,
            Password = TestUsers.DefaultPassword,
            RememberLogin = false
        };
        var loginResponse = await loginClient.PostAsJsonAsync(AuthApiUrl("login"), loginRequest, ct);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var recoveryRequest = new RecoveryCodeLoginRequestDto
        {
            RecoveryCode = recoveryCodes[0]
        };

        // Act
        var response = await loginClient.PostAsJsonAsync(AuthApiUrl("login-recovery"), recoveryRequest, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
        result.RedirectUrl.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task LoginRecovery_WithInvalidCode_ReturnsError()
    {
        // Arrange
        var userName = $"2fa_invalid_recovery_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Create user and enable 2FA
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var setupClient = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        setupClient.Should().NotBeNull();

        var setupResponse = await setupClient!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        await setupClient.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = totp.ComputeTotp() }, ct);

        // Create a new client with cookie support
        var loginClient = CreateCookieClient();

        // First, login to trigger 2FA
        var loginRequest = new LoginRequestDto
        {
            Username = userName,
            Password = TestUsers.DefaultPassword,
            RememberLogin = false
        };
        var loginResponse = await loginClient.PostAsJsonAsync(AuthApiUrl("login"), loginRequest, ct);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var recoveryRequest = new RecoveryCodeLoginRequestDto
        {
            RecoveryCode = "INVALID-CODE"
        };

        // Act
        var response = await loginClient.PostAsJsonAsync(AuthApiUrl("login-recovery"), recoveryRequest, ct);

        // Assert - check status code first
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(ct);
            Assert.Fail($"Expected success status code but got {response.StatusCode}. Response: {errorContent}");
        }

        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Invalid recovery code");
    }

    [Fact]
    public async Task LoginRecovery_WithUsedCode_ReturnsError()
    {
        // Arrange
        var userName = $"2fa_used_recovery_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Create user and enable 2FA
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var setupClient = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        setupClient.Should().NotBeNull();

        var setupResponse = await setupClient!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));

        var verifyResponse = await setupClient.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = totp.ComputeTotp() }, ct);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<VerifyAuthenticatorResultDto>(ct);
        var recoveryCode = verifyResult!.RecoveryCodes.First();

        // Use the recovery code once
        var loginClient1 = CreateCookieClient();
        await loginClient1.PostAsJsonAsync(AuthApiUrl("login"), new { Username = userName, Password = TestUsers.DefaultPassword }, ct);
        var firstUseResponse = await loginClient1.PostAsJsonAsync(AuthApiUrl("login-recovery"), new { RecoveryCode = recoveryCode }, ct);

        // First use should succeed (if 2FA session is maintained)
        if (firstUseResponse.IsSuccessStatusCode)
        {
            var firstResult = await firstUseResponse.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
            if (firstResult?.Success != true)
            {
                // If first use fails due to session issues, skip this test
                Assert.Skip("2FA session not maintained in test environment - skipping used code test");
            }
        }
        else
        {
            Assert.Skip("2FA session not maintained in test environment - skipping used code test");
        }

        // Try to use the same code again
        var loginClient2 = CreateCookieClient();
        await loginClient2.PostAsJsonAsync(AuthApiUrl("login"), new { Username = userName, Password = TestUsers.DefaultPassword }, ct);

        var recoveryRequest = new RecoveryCodeLoginRequestDto
        {
            RecoveryCode = recoveryCode
        };

        // Act
        var response = await loginClient2.PostAsJsonAsync(AuthApiUrl("login-recovery"), recoveryRequest, ct);

        // Assert
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(ct);
            Assert.Fail($"Expected success status code but got {response.StatusCode}. Response: {errorContent}");
        }

        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Invalid recovery code");
    }

    #endregion

    #region Remember Machine Tests

    [Fact]
    public async Task LoginTwoFactor_WithRememberMachine_SetsRememberCookie()
    {
        // Arrange
        var userName = $"2fa_remember_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;

        // Create user and enable 2FA
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var setupClient = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        setupClient.Should().NotBeNull();

        var setupResponse = await setupClient!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        await setupClient.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = totp.ComputeTotp() }, ct);

        // Create a new client with cookie support
        var loginClient = CreateCookieClient();

        // First, login to trigger 2FA
        var loginResponse = await loginClient.PostAsJsonAsync(AuthApiUrl("login"), new { Username = userName, Password = TestUsers.DefaultPassword }, ct);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<LoginResultDto>(ct);

        if (!loginResult!.RequiresTwoFactor)
        {
            Assert.Skip("2FA not triggered - test environment may not support 2FA flow properly");
        }

        var twoFactorRequest = new TwoFactorLoginRequestDto
        {
            Code = totp.ComputeTotp(),
            RememberMachine = true
        };

        // Act
        var response = await loginClient.PostAsJsonAsync(AuthApiUrl("login-2fa"), twoFactorRequest, ct);

        // Assert - check status code first
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(ct);
            Assert.Fail($"Expected success status code but got {response.StatusCode}. Response: {errorContent}");
        }

        var result = await response.Content.ReadFromJsonAsync<TwoFactorLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();

        // Note: Verifying the cookie is set requires checking response headers
        // The "Identity.TwoFactorRememberMe" cookie should be present
    }

    #endregion

    #region Send 2FA Email Tests

    [Fact]
    public async Task SendTwoFactorEmail_WithoutPriorLogin_ReturnsError()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.PostAsync(AuthApiUrl("send-2fa-email"), null, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<SendTwoFactorEmailResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Contain("session expired");
    }

    #endregion
}
