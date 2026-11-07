using System.Security.Claims;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.Login;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Services;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;
using OpenIddict.Abstractions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

public class CrossTenantLoginTests
{
    private readonly ICrossTenantAuthenticationService _crossTenantAuthService;
    private readonly IOctoInteractionService _interaction;
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly UserManager<RtUser> _userManager;
    private readonly IIdentityAuditService _events;
    private readonly IExternalTenantUserMappingStore _externalTenantUserMappingStore;
    private readonly IOctoIdentityProviderStore _identityProviderStore;
    private readonly ICrossTenantUserProvisioningService _crossTenantUserProvisioningService;
    private readonly ILoginGroupAssignmentService _loginGroupAssignmentService;
    private readonly ICrossTenantAncestryGuard _ancestryGuard = Substitute.For<ICrossTenantAncestryGuard>();
    private readonly AuthApiController _sut;

    public CrossTenantLoginTests()
    {
        _interaction = Substitute.For<IOctoInteractionService>();
        var schemeProvider = Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>();
        var clientStore = Substitute.For<IdentityServerPersistence.SystemStores.IOctoClientStore>();
        _events = Substitute.For<IIdentityAuditService>();
        var persistedGrantStore = Substitute.For<IOpenIddictTokenStore<Persistence.IdentityCkModel.Generated.System.Identity.v3.RtOAuthToken>>();
        var ldapAuthService = Substitute.For<ILdapAuthenticationService>();
        _crossTenantAuthService = Substitute.For<ICrossTenantAuthenticationService>();
        _externalTenantUserMappingStore = Substitute.For<IExternalTenantUserMappingStore>();
        _identityProviderStore = Substitute.For<IOctoIdentityProviderStore>();
        var loginGroupAssignmentService = Substitute.For<ILoginGroupAssignmentService>();
        _loginGroupAssignmentService = loginGroupAssignmentService;
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

        _crossTenantUserProvisioningService = Substitute.For<ICrossTenantUserProvisioningService>();

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
            _identityProviderStore,
            loginGroupAssignmentService,
            Substitute.For<IEntraIdVerifiedIdentifierEnrollmentService>(),
            _dataProtectionProvider,
            _crossTenantUserProvisioningService,
            Substitute.For<ICrossTenantSecondFactorVerifier>(),
            new RegisteredTenantsShadowUserChainResolver("OctoSystem"),
            Substitute.For<IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>(),
            Options.Create(new OctoSystemConfiguration { SystemTenantId = "OctoSystem" }),
            Substitute.For<Meshmakers.Octo.Backend.IdentityServices.Services.IUserCredentialChangeService>(),
            new Meshmakers.Octo.Backend.IdentityServices.Services.CrossTenantChallengeReplayGuard(
                new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions())),

            new Meshmakers.Octo.Backend.IdentityServices.Services.SignInRateLimiter(
                Options.Create(new IdentityServerPersistence.Configuration.Options.OctoIdentityServicesOptions())),
            Substitute.For<IOctoTenantLoginProviders>(),
            _ancestryGuard,
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

    /// <summary>
    ///     AB#8367: under CrossTenantAncestry=Enforce a source the tenant registry does not confirm as ancestor gets a 403
    ///     problem with a stable code, so the SPA shows the reason instead of sending the user to the source's login.
    /// </summary>
    [Fact]
    public async Task GetCrossTenantToken_Enforce_SourceNotRegistryAncestor_Returns403ProblemWithCode()
    {
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("ec-apphost", CreateAuthenticatedUser(userId, "admin"));
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("mrotest", "ec-apphost", userId)
            .Returns((CrossTenantAuthResult?)null);
        _ancestryGuard.Mode.Returns(CrossTenantAncestryMode.Enforce);
        _ancestryGuard.GetRegistryAncestorsAsync("mrotest").Returns(new[] { "octosystem" });

        var result = await _sut.GetCrossTenantToken(new CrossTenantTokenRequestDto { TargetTenantId = "mrotest" });

        var problem = result.Result.Should().BeOfType<ObjectResult>().Subject;
        problem.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        problem.Value.Should().BeOfType<ProblemDetails>().Which.Extensions["code"].Should()
            .Be(Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers.CrossTenantAncestryProblems
                .SourceTenantNotAncestorCode);
    }

    /// <summary>
    ///     AB#8367: a refusal for any other reason (unknown or locked user, provider missing) under Enforce stays the plain
    ///     403, and so does every refusal under Warn — the registry did not refuse.
    /// </summary>
    [Theory]
    [InlineData(CrossTenantAncestryMode.Enforce, "OctoSystem")]
    [InlineData(CrossTenantAncestryMode.Warn, "somewhere-else")]
    public async Task GetCrossTenantToken_RefusedButNotByTheRegistry_ReturnsPlainForbid(CrossTenantAncestryMode mode,
        string registryParent)
    {
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("OctoSystem", CreateAuthenticatedUser(userId, "admin"));
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns((CrossTenantAuthResult?)null);
        _ancestryGuard.Mode.Returns(mode);
        _ancestryGuard.GetRegistryAncestorsAsync("meshtest").Returns(new[] { registryParent });

        var result = await _sut.GetCrossTenantToken(new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });

        result.Result.Should().BeOfType<ForbidResult>();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task GetCrossTenantToken_SourceUserWithTwoFactor_NeedsSecondFactorEvidence(bool sessionHasMfa,
        bool expectToken)
    {
        // AB#7804: amr=mfa on the source session is the evidence.
        var userId = Guid.NewGuid().ToString("N");
        var claims = new List<Claim> { new("sub", userId), new(ClaimTypes.Name, "admin") };
        claims.Add(new Claim("amr", sessionHasMfa ? "mfa" : "pwd"));
        SetupControllerContext("OctoSystem", new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth")));
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", userId)
            .Returns(new CrossTenantAuthResult
            {
                SourceTenantId = "OctoSystem",
                SourceUserId = userId,
                SourceUserName = "admin",
                SourceUserRequiresSecondFactor = true
            });

        var result = await _sut.GetCrossTenantToken(new CrossTenantTokenRequestDto { TargetTenantId = "meshtest" });

        if (expectToken)
        {
            result.Value!.Token.Should().NotBeNullOrEmpty();
        }
        else
        {
            result.Result.Should().BeOfType<ForbidResult>();
        }
    }

    #endregion

    #region CrossTenantLogin Tests

    [Fact]
    public async Task PasswordLogin_SourceUserWithTwoFactor_WhoseOptionsCannotBeRead_GetsNoSession()
    {
        // AB#7861: the source user needs a second factor, but its options cannot be read (user gone, tenant
        // unreadable). Neither a challenge nor a session: the login fails like a wrong password.
        SetupControllerContext("meshtest");
        _signInManager.PasswordSignInAsync("admin", "secret", false, true)
            .Returns(Microsoft.AspNetCore.Identity.SignInResult.Failed);
        _crossTenantAuthService.AuthenticateAsync("meshtest", "admin", "secret").Returns(new CrossTenantAuthResult
        {
            SourceTenantId = "OctoSystem",
            SourceUserId = Guid.NewGuid().ToString("N"),
            SourceUserName = "admin",
            SourceUserRequiresSecondFactor = true
        });
        _identityProviderStore.GetAllAsync().Returns(Array.Empty<RtIdentityProvider>());
        // ICrossTenantSecondFactorVerifier is a bare substitute: GetOptionsAsync answers null.

        var result = await _sut.Login(new LoginRequestDto { Username = "admin", Password = "secret" });

        result.Value!.Success.Should().BeFalse();
        result.Value.RequiresTwoFactor.Should().BeFalse("no challenge without readable second-factor options");
        await _signInManager.DidNotReceiveWithAnyArgs().SignInAsync(default!, default(bool), default);
        await _signInManager.DidNotReceiveWithAnyArgs().SignInWithClaimsAsync(default!, default(bool), default!);
    }

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
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_OctoSystem_admin"
        };
        _crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
                Arg.Any<CrossTenantAuthResult>(), Arg.Any<string>(), Arg.Is(false))
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
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_OctoSystem_admin"
        };
        _crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
                Arg.Any<CrossTenantAuthResult>(), Arg.Any<string>(), Arg.Is(false))
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
    public async Task CrossTenantLogin_NewUser_SelfRegistrationDisabled_WithoutMapping_Fails()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        var token = await CreateValidTokenAsync(userId);

        SetupControllerContext("meshtest");
        SetupSelfRegistrationDisabledProvider();
        _userManager.FindByNameAsync(Arg.Any<string>()).Returns((RtUser?)null);
        _crossTenantUserProvisioningService.IsExplicitlyProvisionedAsync(Arg.Any<CrossTenantAuthResult>())
            .Returns(false);

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = token });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Self-registration");
        await _signInManager.DidNotReceive().SignInAsync(Arg.Any<RtUser>(), Arg.Any<bool>());
    }

    [Fact]
    public async Task CrossTenantLogin_NewUser_SelfRegistrationDisabled_WithMapping_Succeeds()
    {
        // Arrange: AB#5015 — an admin-provisioned mapping is explicit provisioning, not
        // self-registration, so the first login must create the shadow user and succeed.
        var userId = Guid.NewGuid().ToString("N");
        var token = await CreateValidTokenAsync(userId);

        SetupControllerContext("meshtest");
        SetupSelfRegistrationDisabledProvider();
        _userManager.FindByNameAsync(Arg.Any<string>()).Returns((RtUser?)null);
        _crossTenantUserProvisioningService.IsExplicitlyProvisionedAsync(
                Arg.Is<CrossTenantAuthResult>(r => r.SourceTenantId == "OctoSystem" && r.SourceUserId == userId))
            .Returns(true);

        var localUser = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_OctoSystem_admin"
        };
        _crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
                Arg.Any<CrossTenantAuthResult>(), Arg.Any<string>(), Arg.Is(false))
            .Returns(localUser);
        _interaction.IsValidReturnUrl(Arg.Any<string>()).Returns(false);

        // Act
        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = token });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeTrue();
        await _signInManager.Received(1).SignInAsync(localUser, false);
    }

    [Fact]
    public async Task CrossTenantLogin_ShadowUserFromOtherLoginPath_IsExistingUser_NoSelfRegistrationGate()
    {
        // AB#5708: the person already has a shadow user created by another login path (different
        // xt_ name). That is an existing user — neither the self-registration gate nor the new-user
        // group assignment applies.
        var userId = Guid.NewGuid().ToString("N");
        var token = await CreateValidTokenAsync(userId);

        SetupControllerContext("meshtest");
        SetupSelfRegistrationDisabledProvider();
        _crossTenantUserProvisioningService.IsExplicitlyProvisionedAsync(Arg.Any<CrossTenantAuthResult>())
            .Returns(false);

        var existingShadow = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_parent_xt_OctoSystem_admin"
        };
        _crossTenantUserProvisioningService.FindCrossTenantUserAsync(Arg.Any<CrossTenantAuthResult>())
            .Returns(existingShadow);
        _crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
                Arg.Any<CrossTenantAuthResult>(), Arg.Any<string>(), Arg.Is(false))
            .Returns(existingShadow);
        _interaction.IsValidReturnUrl(Arg.Any<string>()).Returns(false);

        var result = await _sut.CrossTenantLogin(
            new CrossTenantLoginRequestDto { Token = token });

        result.Value!.Success.Should().BeTrue();
        await _signInManager.Received(1).SignInAsync(existingShadow, false);
        await _loginGroupAssignmentService.DidNotReceive()
            .AssignGroupsAsync(Arg.Any<RtUser>(), Arg.Any<RtIdentityProvider?>());
    }

    private async Task<string> CreateValidTokenAsync(string userId)
    {
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
        return tokenResult.Value!.Token;
    }

    private void SetupSelfRegistrationDisabledProvider()
    {
        _identityProviderStore.GetAllAsync().Returns(
        [
            new RtOctoTenantIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = "ParentTenant_OctoSystem",
                ParentTenantId = "OctoSystem",
                IsEnabled = true,
                AllowSelfRegistration = false
            }
        ]);
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

    #region Tenant switch (AB#8439)

    /// <summary>
    ///     Arranges a tenant switch in <c>meshtest</c> by the caller <c>xt_OctoSystem_admin</c>, whose source identity
    ///     in <c>OctoSystem</c> is <paramref name="sourceUserId" />.
    /// </summary>
    private void SetupTenantSwitch(string sourceUserId, RtUser caller)
    {
        SetupControllerContext("meshtest", CreateAuthenticatedUser(caller.RtId.ToString(), caller.UserName!));
        _userManager.FindByIdAsync(caller.RtId.ToString()).Returns(caller);
        _userManager.GetRolesAsync(Arg.Any<RtUser>()).Returns(new List<string>());
        _crossTenantAuthService.FindUserIdByNameInTenantAsync("OctoSystem", "admin").Returns(sourceUserId);
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "OctoSystem", sourceUserId)
            .Returns(new CrossTenantAuthResult
            {
                SourceTenantId = "OctoSystem",
                SourceUserId = sourceUserId,
                SourceUserName = "admin"
            });
    }

    [Fact]
    public async Task TenantSwitch_ExistingShadowUser_SignsInWithoutStoringAMapping()
    {
        var sourceUserId = Guid.NewGuid().ToString("N");
        var caller = new RtUser { RtId = OctoObjectId.GenerateNewId(), UserName = "xt_OctoSystem_admin" };
        SetupTenantSwitch(sourceUserId, caller);
        _crossTenantUserProvisioningService.FindCrossTenantUserAsync(Arg.Any<CrossTenantAuthResult>()).Returns(caller);
        _crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
                Arg.Any<CrossTenantAuthResult>(), Arg.Any<string>(), Arg.Any<bool>())
            .Returns(caller);

        var result = await _sut.SwitchTenant(new TenantSwitchRequestDto { SourceTenantId = "OctoSystem" });

        result.Value!.Success.Should().BeTrue(result.Value.ErrorMessage);
        await _crossTenantUserProvisioningService.Received(1).FindOrCreateCrossTenantUserAsync(
            Arg.Any<CrossTenantAuthResult>(), Arg.Is("meshtest"), Arg.Is(false));
        await _crossTenantUserProvisioningService.DidNotReceive().FindOrCreateCrossTenantUserAsync(
            Arg.Any<CrossTenantAuthResult>(), Arg.Any<string>(), Arg.Is(true));
    }

    [Fact]
    public async Task TenantSwitch_NewShadowUser_SelfRegistrationDisabled_WithoutMapping_IsRefused()
    {
        // AB#8439: the switch used to create the shadow user (and a bare mapping) without the self-registration gate.
        var sourceUserId = Guid.NewGuid().ToString("N");
        var caller = new RtUser { RtId = OctoObjectId.GenerateNewId(), UserName = "xt_OctoSystem_admin" };
        SetupTenantSwitch(sourceUserId, caller);
        SetupSelfRegistrationDisabledProvider();
        _crossTenantUserProvisioningService.FindCrossTenantUserAsync(Arg.Any<CrossTenantAuthResult>())
            .Returns((RtUser?)null);
        _crossTenantUserProvisioningService.IsExplicitlyProvisionedAsync(Arg.Any<CrossTenantAuthResult>())
            .Returns(false);

        var result = await _sut.SwitchTenant(new TenantSwitchRequestDto { SourceTenantId = "OctoSystem" });

        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Self-registration");
        await _crossTenantUserProvisioningService.DidNotReceiveWithAnyArgs()
            .FindOrCreateCrossTenantUserAsync(default!, default!, default);
        await _signInManager.DidNotReceive().SignInAsync(Arg.Any<RtUser>(), Arg.Any<bool>());
    }

    [Fact]
    public async Task TenantSwitch_NewShadowUser_SelfRegistrationDisabled_WithAdminMapping_SignsIn()
    {
        var sourceUserId = Guid.NewGuid().ToString("N");
        var caller = new RtUser { RtId = OctoObjectId.GenerateNewId(), UserName = "xt_OctoSystem_admin" };
        SetupTenantSwitch(sourceUserId, caller);
        SetupSelfRegistrationDisabledProvider();
        _crossTenantUserProvisioningService.FindCrossTenantUserAsync(Arg.Any<CrossTenantAuthResult>())
            .Returns((RtUser?)null);
        _crossTenantUserProvisioningService.IsExplicitlyProvisionedAsync(Arg.Any<CrossTenantAuthResult>())
            .Returns(true);
        var shadow = new RtUser { RtId = OctoObjectId.GenerateNewId(), UserName = "xt_OctoSystem_admin" };
        _crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
                Arg.Any<CrossTenantAuthResult>(), Arg.Is("meshtest"), Arg.Is(false))
            .Returns(shadow);

        var result = await _sut.SwitchTenant(new TenantSwitchRequestDto { SourceTenantId = "OctoSystem" });

        result.Value!.Success.Should().BeTrue(result.Value.ErrorMessage);
        await _signInManager.Received(1).SignInAsync(shadow, false);
    }

    #endregion
}
