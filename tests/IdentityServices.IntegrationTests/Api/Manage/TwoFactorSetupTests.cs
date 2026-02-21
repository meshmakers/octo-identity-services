using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Helpers;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using OtpNet;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Manage;

/// <summary>
/// Integration tests for the two-factor authentication setup endpoints.
/// </summary>
public class TwoFactorSetupTests : IntegrationTestBase
{
    public TwoFactorSetupTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    #region GetTwoFactorStatus Tests

    [Fact]
    public async Task GetTwoFactorStatus_WhenNotEnabled_ReturnsDisabledStatus()
    {
        // Arrange
        var userName = $"2fa_status_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // Act
        var response = await client!.GetAsync(ManageApiUrl("2fa/status"), ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var status = await response.Content.ReadFromJsonAsync<TwoFactorStatusDto>(ct);
        status.Should().NotBeNull();
        status!.Enabled.Should().BeFalse();
        status.HasAuthenticator.Should().BeFalse();
        status.RecoveryCodesLeft.Should().Be(0);
    }

    [Fact]
    public async Task GetTwoFactorStatus_WhenEnabled_ReturnsEnabledStatus()
    {
        // Arrange - Create user and enable 2FA through the setup flow
        var userName = $"2fa_enabled_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // Enable 2FA by setting up and verifying the authenticator
        var setupResponse = await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        setup.Should().NotBeNull();

        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        var code = totp.ComputeTotp();

        var verifyResponse = await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = code }, ct);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<VerifyAuthenticatorResultDto>(ct);
        verifyResult!.Success.Should().BeTrue("2FA should be enabled successfully");

        // Act
        var response = await client.GetAsync(ManageApiUrl("2fa/status"), ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var status = await response.Content.ReadFromJsonAsync<TwoFactorStatusDto>(ct);
        status.Should().NotBeNull();
        status!.Enabled.Should().BeTrue();
        status.HasAuthenticator.Should().BeTrue();
        status.RecoveryCodesLeft.Should().Be(10);
    }

    [Fact]
    public async Task GetTwoFactorStatus_WithoutAuthentication_ReturnsUnauthorized()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.GetAsync(ManageApiUrl("2fa/status"), ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    #endregion

    #region SetupAuthenticator Tests

    [Fact]
    public async Task SetupAuthenticator_ReturnsQrCodeAndSharedKey()
    {
        // Arrange
        var userName = $"2fa_setup_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // Act
        var response = await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var setup = await response.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        setup.Should().NotBeNull();
        setup!.SharedKey.Should().NotBeNullOrEmpty();
        setup.QrCodeUri.Should().NotBeNullOrEmpty();
        setup.QrCodeImage.Should().NotBeNullOrEmpty();

        // Verify QR code URI format
        setup.QrCodeUri.Should().StartWith("otpauth://totp/");
        setup.QrCodeUri.Should().Contain("OctoMesh");

        // Verify QR code image is valid base64
        var isValidBase64 = IsValidBase64(setup.QrCodeImage);
        isValidBase64.Should().BeTrue();
    }

    [Fact]
    public async Task SetupAuthenticator_WithoutAuthentication_ReturnsUnauthorized()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    #endregion

    #region VerifyAuthenticator Tests

    [Fact]
    public async Task VerifyAuthenticator_WithValidCode_EnablesTwoFactor()
    {
        // Arrange
        var userName = $"2fa_verify_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // First, setup the authenticator
        var setupResponse = await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);
        setup.Should().NotBeNull();

        // Generate a valid TOTP code
        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        var code = totp.ComputeTotp();

        var request = new VerifyAuthenticatorRequestDto { Code = code };

        // Act
        var response = await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<VerifyAuthenticatorResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
        result.RecoveryCodes.Should().HaveCount(10);
        result.ErrorMessage.Should().BeNull();

        // Verify 2FA is now enabled
        var statusResponse = await client.GetAsync(ManageApiUrl("2fa/status"), ct);
        var status = await statusResponse.Content.ReadFromJsonAsync<TwoFactorStatusDto>(ct);
        status!.Enabled.Should().BeTrue();
        status.HasAuthenticator.Should().BeTrue();
        status.RecoveryCodesLeft.Should().Be(10);
    }

    [Fact]
    public async Task VerifyAuthenticator_WithInvalidCode_Fails()
    {
        // Arrange
        var userName = $"2fa_invalid_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // First, setup the authenticator
        await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);

        var request = new VerifyAuthenticatorRequestDto { Code = "000000" };

        // Act
        var response = await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<VerifyAuthenticatorResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Verification code is invalid");
        result.RecoveryCodes.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAuthenticator_WithoutAuthentication_ReturnsUnauthorized()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var request = new VerifyAuthenticatorRequestDto { Code = "123456" };

        // Act
        var response = await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    #endregion

    #region DisableTwoFactor Tests

    [Fact]
    public async Task DisableTwoFactor_WithValidCode_DisablesTwoFactor()
    {
        // Arrange
        var userName = $"2fa_disable_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // First, enable 2FA
        var setupResponse = await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);

        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        var enableCode = totp.ComputeTotp();

        await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = enableCode }, ct);

        // Generate a new code for disabling
        var disableCode = totp.ComputeTotp();
        var request = new DisableTwoFactorRequestDto { Code = disableCode };

        // Act
        var response = await client.PostAsJsonAsync(ManageApiUrl("2fa/disable"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<DisableTwoFactorResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeTrue();
        result.ErrorMessage.Should().BeNull();

        // Verify 2FA is now disabled
        var statusResponse = await client.GetAsync(ManageApiUrl("2fa/status"), ct);
        var status = await statusResponse.Content.ReadFromJsonAsync<TwoFactorStatusDto>(ct);
        status!.Enabled.Should().BeFalse();
        status.HasAuthenticator.Should().BeFalse();
    }

    [Fact]
    public async Task DisableTwoFactor_WithInvalidCode_Fails()
    {
        // Arrange
        var userName = $"2fa_disable_invalid_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // First, enable 2FA
        var setupResponse = await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);

        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        var enableCode = totp.ComputeTotp();

        await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = enableCode }, ct);

        var request = new DisableTwoFactorRequestDto { Code = "000000" };

        // Act
        var response = await client.PostAsJsonAsync(ManageApiUrl("2fa/disable"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<DisableTwoFactorResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Verification code is invalid");
    }

    #endregion

    #region GenerateRecoveryCodes Tests

    [Fact]
    public async Task GenerateRecoveryCodes_WhenTwoFactorEnabled_Returns10Codes()
    {
        // Arrange
        var userName = $"2fa_recovery_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // First, enable 2FA
        var setupResponse = await client!.PostAsync(ManageApiUrl("2fa/authenticator/setup"), null, ct);
        var setup = await setupResponse.Content.ReadFromJsonAsync<AuthenticatorSetupDto>(ct);

        var sharedKey = setup!.SharedKey.Replace(" ", string.Empty).ToUpperInvariant();
        var totp = new Totp(Base32Encoding.ToBytes(sharedKey));
        var code = totp.ComputeTotp();

        await client.PostAsJsonAsync(ManageApiUrl("2fa/authenticator/verify"), new { Code = code }, ct);

        // Act
        var response = await client.PostAsync(ManageApiUrl("2fa/recovery-codes/generate"), null, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<GenerateRecoveryCodesResultDto>(ct);
        result.Should().NotBeNull();
        result!.RecoveryCodes.Should().HaveCount(10);
        result.RecoveryCodes.All(c => !string.IsNullOrEmpty(c)).Should().BeTrue();
    }

    [Fact]
    public async Task GenerateRecoveryCodes_WhenTwoFactorNotEnabled_ReturnsBadRequest()
    {
        // Arrange
        var userName = $"2fa_recovery_noenable_{Guid.NewGuid():N}";
        var ct = TestContext.Current.CancellationToken;
        await CreateTestUserAsync(userName, password: TestUsers.DefaultPassword);
        var client = await LoginAndGetAuthenticatedClientAsync(userName, TestUsers.DefaultPassword, ct);
        client.Should().NotBeNull();

        // Act
        var response = await client!.PostAsync(ManageApiUrl("2fa/recovery-codes/generate"), null, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    #endregion

    #region Helper Methods

    private static bool IsValidBase64(string base64)
    {
        try
        {
            Convert.FromBase64String(base64);
            return true;
        }
        catch
        {
            return false;
        }
    }

    #endregion
}
