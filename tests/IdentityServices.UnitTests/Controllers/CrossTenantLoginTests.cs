using System.Security.Claims;
using System.Text.Json;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Services;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

public class CrossTenantLoginTests
{
    private readonly ICrossTenantAuthenticationService _crossTenantAuthService;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly UserManager<RtUser> _userManager;
    private readonly IEventService _events;
    private readonly IExternalTenantUserMappingStore _externalTenantUserMappingStore;
    private readonly AuthApiController _sut;

    public CrossTenantLoginTests()
    {
        _interaction = Substitute.For<IIdentityServerInteractionService>();
        var schemeProvider = Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        var clientStore = Substitute.For<IClientStore>();
        _events = Substitute.For<IEventService>();
        var persistedGrantStore = Substitute.For<IPersistedGrantStore>();
        var ldapAuthService = Substitute.For<ILdapAuthenticationService>();
        _crossTenantAuthService = Substitute.For<ICrossTenantAuthenticationService>();
        _externalTenantUserMappingStore = Substitute.For<IExternalTenantUserMappingStore>();
        var identityProviderStore = Substitute.For<IOctoIdentityProviderStore>();
        _dataProtectionProvider = new EphemeralDataProtectionProvider();
        var logger = Substitute.For<ILogger<AuthApiController>>();

        // Create UserManager mock
        var userStore = Substitute.For<IUserStore<RtUser>>();
        _userManager = Substitute.For<UserManager<RtUser>>(
            userStore,
            Substitute.For<IOptions<IdentityOptions>>(),
            Substitute.For<IPasswordHasher<RtUser>>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            Substitute.For<ILookupNormalizer>(),
            Substitute.For<IdentityErrorDescriber>(),
            Substitute.For<IServiceProvider>(),
            Substitute.For<ILogger<UserManager<RtUser>>>());

        // Create SignInManager mock
        _signInManager = Substitute.For<SignInManager<RtUser>>(
            _userManager,
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IUserClaimsPrincipalFactory<RtUser>>(),
            Substitute.For<IOptions<IdentityOptions>>(),
            Substitute.For<ILogger<SignInManager<RtUser>>>(),
            Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>(),
            Substitute.For<IUserConfirmation<RtUser>>());

        _sut = new AuthApiController(
            _interaction,
            schemeProvider,
            clientStore,
            _signInManager,
            _userManager,
            _events,
            persistedGrantStore,
            ldapAuthService,
            _crossTenantAuthService,
            _externalTenantUserMappingStore,
            identityProviderStore,
            _dataProtectionProvider,
            logger);
    }

    private void SetupControllerContext(string tenantId, ClaimsPrincipal? user = null)
    {
        var httpContext = new DefaultHttpContext();
        if (user != null)
        {
            httpContext.User = user;
        }

        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = httpContext,
            RouteData = new RouteData(new RouteValueDictionary { { "tenantId", tenantId } })
        };
    }

    private static ClaimsPrincipal CreateAuthenticatedUser(string userId, string userName)
    {
        var claims = new[]
        {
            new Claim("sub", userId),
            new Claim(ClaimTypes.Name, userName)
        };
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
    }

    #region GetCrossTenantToken Tests

    [Fact]
    public async Task GetCrossTenantToken_WithAuthenticatedUser_ReturnsToken()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        var user = CreateAuthenticatedUser(userId, "admin");
        SetupControllerContext("OctoSystem", user);

        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns(new CrossTenantAuthResult
            {
                SourceTenantId = "OctoSystem",
                SourceUserId = userId,
                SourceUserName = "admin"
            });

        // Act
        var result = await _sut.GetCrossTenantToken(
            new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Token.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetCrossTenantToken_WithUnauthenticatedUser_ReturnsUnauthorized()
    {
        // Arrange: no user claims → empty sub
        SetupControllerContext("OctoSystem");

        // Act
        var result = await _sut.GetCrossTenantToken(
            new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });

        // Assert
        result.Result.Should().BeOfType<UnauthorizedResult>();
    }

    [Fact]
    public async Task GetCrossTenantToken_WhenSourceNotAncestor_ReturnsForbid()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        var user = CreateAuthenticatedUser(userId, "admin");
        SetupControllerContext("OctoSystem", user);

        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns((CrossTenantAuthResult?)null);

        // Act
        var result = await _sut.GetCrossTenantToken(
            new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });

        // Assert
        result.Result.Should().BeOfType<ForbidResult>();
    }

    #endregion

    #region CrossTenantLogin Tests

    [Fact]
    public async Task CrossTenantLogin_WithValidToken_Succeeds()
    {
        // Arrange: first generate a valid token
        var userId = Guid.NewGuid().ToString("N");
        var user = CreateAuthenticatedUser(userId, "admin");
        SetupControllerContext("OctoSystem", user);

        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns(new CrossTenantAuthResult
            {
                SourceTenantId = "OctoSystem",
                SourceUserId = userId,
                SourceUserName = "admin",
                Email = "admin@test.com"
            });

        var tokenResult = await _sut.GetCrossTenantToken(
            new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });
        var token = tokenResult.Value!.Token;

        // Now switch to the target tenant context
        SetupControllerContext("meshtest");

        var localUser = new RtUser
        {
            RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
            UserName = "xt_OctoSystem_admin"
        };
        _userManager.FindByNameAsync("xt_OctoSystem_admin")
            .Returns(localUser);

        _interaction.IsValidReturnUrl(Arg.Any<string>()).Returns(false);

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = token, ReturnUrl = null });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeTrue();
        result.Value.RedirectUrl.Should().Be("/meshtest/manage");
        await _signInManager.Received(1).SignInAsync(localUser, false);
    }

    [Fact]
    public async Task CrossTenantLogin_WithExpiredToken_Fails()
    {
        // Arrange: create a token with an old timestamp
        var protector = _dataProtectionProvider.CreateProtector("CrossTenantLogin");
        var payload = JsonSerializer.Serialize(new
        {
            SourceTenantId = "OctoSystem",
            SourceUserId = Guid.NewGuid().ToString("N"),
            TargetTenantId = "meshtest",
            Timestamp = DateTimeOffset.UtcNow.AddSeconds(-120).ToUnixTimeSeconds()
        });
        var expiredToken = protector.Protect(payload);

        SetupControllerContext("meshtest");

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = expiredToken });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("expired");
    }

    [Fact]
    public async Task CrossTenantLogin_WithWrongTargetTenant_Fails()
    {
        // Arrange: generate token for "meshtest" but try to use it on "othertenant"
        var userId = Guid.NewGuid().ToString("N");
        var user = CreateAuthenticatedUser(userId, "admin");
        SetupControllerContext("OctoSystem", user);

        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns(new CrossTenantAuthResult
            {
                SourceTenantId = "OctoSystem",
                SourceUserId = userId,
                SourceUserName = "admin"
            });

        var tokenResult = await _sut.GetCrossTenantToken(
            new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });
        var token = tokenResult.Value!.Token;

        // Switch to a different tenant than the token was issued for
        SetupControllerContext("othertenant");

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = token });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("different tenant");
    }

    [Fact]
    public async Task CrossTenantLogin_WithInvalidToken_Fails()
    {
        // Arrange
        SetupControllerContext("meshtest");

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = "not-a-valid-token" });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Invalid or expired");
    }

    [Fact]
    public async Task CrossTenantLogin_WithValidToken_AndReturnUrl_UsesReturnUrl()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        var user = CreateAuthenticatedUser(userId, "admin");
        SetupControllerContext("OctoSystem", user);

        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns(new CrossTenantAuthResult
            {
                SourceTenantId = "OctoSystem",
                SourceUserId = userId,
                SourceUserName = "admin"
            });

        var tokenResult = await _sut.GetCrossTenantToken(
            new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });
        var token = tokenResult.Value!.Token;

        SetupControllerContext("meshtest");

        var localUser = new RtUser
        {
            RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
            UserName = "xt_OctoSystem_admin"
        };
        _userManager.FindByNameAsync("xt_OctoSystem_admin")
            .Returns(localUser);

        var returnUrl = "/meshtest/connect/authorize?client_id=test";
        _interaction.IsValidReturnUrl(returnUrl).Returns(true);

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = token, ReturnUrl = returnUrl });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeTrue();
        result.Value.RedirectUrl.Should().Be(returnUrl);
    }

    [Fact]
    public async Task CrossTenantLogin_WhenAccessDenied_Fails()
    {
        // Arrange: generate a valid token but then deny access on the second validation
        var userId = Guid.NewGuid().ToString("N");
        var user = CreateAuthenticatedUser(userId, "admin");
        SetupControllerContext("OctoSystem", user);

        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns(new CrossTenantAuthResult
            {
                SourceTenantId = "OctoSystem",
                SourceUserId = userId,
                SourceUserName = "admin"
            });

        var tokenResult = await _sut.GetCrossTenantToken(
            new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });
        var token = tokenResult.Value!.Token;

        // Now switch context and make the second validation fail
        SetupControllerContext("meshtest");
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns((CrossTenantAuthResult?)null);

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = token });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("denied");
    }

    #endregion
}
