using System.Security.Claims;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

public class DeviceApiControllerTests
{
    private readonly IDeviceFlowInteractionService _deviceInteraction;
    private readonly IEventService _events;
    private readonly ICrossTenantAuthenticationService _crossTenantAuthService;
    private readonly ICrossTenantUserProvisioningService _crossTenantUserProvisioningService;
    private readonly IOctoIdentityProviderStore _identityProviderStore;
    private readonly UserManager<RtUser> _userManager;
    private readonly SignInManager<RtUser> _signInManager;
    private readonly DeviceApiController _sut;

    public DeviceApiControllerTests()
    {
        _deviceInteraction = Substitute.For<IDeviceFlowInteractionService>();
        _events = Substitute.For<IEventService>();
        _crossTenantAuthService = Substitute.For<ICrossTenantAuthenticationService>();
        _crossTenantUserProvisioningService = Substitute.For<ICrossTenantUserProvisioningService>();
        _identityProviderStore = Substitute.For<IOctoIdentityProviderStore>();
        var logger = Substitute.For<ILogger<DeviceApiController>>();

        var userStore = Substitute.For<IUserStore<RtUser>>();
        _userManager = Substitute.For<UserManager<RtUser>>(
            userStore,
            Substitute.For<Microsoft.Extensions.Options.IOptions<IdentityOptions>>(),
            Substitute.For<IPasswordHasher<RtUser>>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            Substitute.For<ILookupNormalizer>(),
            Substitute.For<IdentityErrorDescriber>(),
            Substitute.For<IServiceProvider>(),
            Substitute.For<ILogger<UserManager<RtUser>>>());

        _signInManager = Substitute.For<SignInManager<RtUser>>(
            _userManager,
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IUserClaimsPrincipalFactory<RtUser>>(),
            Substitute.For<Microsoft.Extensions.Options.IOptions<IdentityOptions>>(),
            Substitute.For<ILogger<SignInManager<RtUser>>>(),
            Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>(),
            Substitute.For<IUserConfirmation<RtUser>>());

        _sut = new DeviceApiController(
            _deviceInteraction,
            _events,
            _crossTenantAuthService,
            _crossTenantUserProvisioningService,
            _identityProviderStore,
            _userManager,
            _signInManager,
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

    private static ClaimsPrincipal CreateAuthenticatedUser(string userId)
    {
        var claims = new[]
        {
            new Claim("sub", userId),
            new Claim(ClaimTypes.Name, "testuser")
        };
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
    }

    private void SetupDeviceInteractionReturnsContext(string userCode)
    {
        var context = new DeviceFlowAuthorizationRequest
        {
            Client = new Client { ClientId = "octo-cli", ClientName = "Octo CLI" },
            ValidatedResources = new ResourceValidationResult()
        };
        _deviceInteraction.GetAuthorizationContextAsync(userCode)
            .Returns(context);
    }

    #region Authorize - Invalid/Expired Device Code

    [Fact]
    public async Task Authorize_WithInvalidUserCode_ReturnsFailure()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));

        _deviceInteraction.GetAuthorizationContextAsync("invalid-code")
            .Returns((DeviceFlowAuthorizationRequest?)null);

        // Act
        var result = await _sut.Authorize(new DeviceAuthorizationRequestDto
        {
            UserCode = "invalid-code"
        });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Invalid or expired");
    }

    #endregion

    #region Authorize - Same Tenant (No Cross-Tenant)

    [Fact]
    public async Task Authorize_WithLocalUser_SucceedsWithoutCrossTenantProvisioning()
    {
        // Arrange
        var userRtId = OctoObjectId.GenerateNewId();
        var userId = userRtId.ToString();
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));
        SetupDeviceInteractionReturnsContext("valid-code");

        var localUser = new RtUser
        {
            RtId = userRtId,
            UserName = "localuser"
        };
        _userManager.FindByIdAsync(userId).Returns(localUser);

        // Act
        var result = await _sut.Authorize(new DeviceAuthorizationRequestDto
        {
            UserCode = "valid-code",
            ScopesConsented = ["openid", "profile"]
        });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeTrue();

        // Should NOT attempt cross-tenant provisioning
        await _crossTenantAuthService.DidNotReceive()
            .ValidateCrossTenantAccessAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
        await _crossTenantUserProvisioningService.DidNotReceive()
            .FindOrCreateCrossTenantUserAsync(Arg.Any<CrossTenantAuthResult>(), Arg.Any<string>());
        await _signInManager.DidNotReceive()
            .SignInAsync(Arg.Any<RtUser>(), Arg.Any<bool>());

        // Should still handle the device request
        await _deviceInteraction.Received(1).HandleRequestAsync("valid-code", Arg.Any<ConsentResponse>());
    }

    #endregion

    #region Authorize - Cross-Tenant Provisioning

    [Fact]
    public async Task Authorize_WithCrossTenantUser_ProvisionsShadowUserAndSucceeds()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));
        SetupDeviceInteractionReturnsContext("valid-code");

        // User does NOT exist in the target tenant
        _userManager.FindByIdAsync(userId).Returns((RtUser?)null);

        // Tenant has an OctoTenantIdentityProvider pointing to octosystem
        var provider = new RtOctoTenantIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            IsEnabled = true,
            ParentTenantId = "octosystem"
        };
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { provider });

        // Cross-tenant validation succeeds
        var crossTenantResult = new CrossTenantAuthResult
        {
            SourceTenantId = "octosystem",
            SourceUserId = userId,
            SourceUserName = "admin@test.com",
            Email = "admin@test.com"
        };
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "octosystem", userId)
            .Returns(crossTenantResult);

        // Shadow user is provisioned
        var shadowUser = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = "xt_octosystem_admin@test.com"
        };
        _crossTenantUserProvisioningService
            .FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest")
            .Returns(shadowUser);

        // Act
        var result = await _sut.Authorize(new DeviceAuthorizationRequestDto
        {
            UserCode = "valid-code",
            ScopesConsented = ["openid", "profile"]
        });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeTrue();

        // Verify cross-tenant provisioning occurred
        await _crossTenantUserProvisioningService.Received(1)
            .FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest");

        // Verify re-sign-in with the shadow user
        await _signInManager.Received(1).SignInAsync(shadowUser, false);

        // Should still handle the device request
        await _deviceInteraction.Received(1).HandleRequestAsync("valid-code", Arg.Any<ConsentResponse>());
    }

    [Fact]
    public async Task Authorize_WithCrossTenantUser_WhenAccessDenied_ReturnsFailure()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));
        SetupDeviceInteractionReturnsContext("valid-code");

        _userManager.FindByIdAsync(userId).Returns((RtUser?)null);

        var provider = new RtOctoTenantIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            IsEnabled = true,
            ParentTenantId = "octosystem"
        };
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { provider });

        // Cross-tenant validation FAILS
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "octosystem", userId)
            .Returns((CrossTenantAuthResult?)null);

        // Act
        var result = await _sut.Authorize(new DeviceAuthorizationRequestDto
        {
            UserCode = "valid-code"
        });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Cross-tenant access denied");

        // Should NOT handle the device request
        await _deviceInteraction.DidNotReceive()
            .HandleRequestAsync(Arg.Any<string>(), Arg.Any<ConsentResponse>());
    }

    [Fact]
    public async Task Authorize_WithCrossTenantUser_WhenProvisioningFails_ReturnsFailure()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));
        SetupDeviceInteractionReturnsContext("valid-code");

        _userManager.FindByIdAsync(userId).Returns((RtUser?)null);

        var provider = new RtOctoTenantIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            IsEnabled = true,
            ParentTenantId = "octosystem"
        };
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { provider });

        var crossTenantResult = new CrossTenantAuthResult
        {
            SourceTenantId = "octosystem",
            SourceUserId = userId,
            SourceUserName = "admin@test.com"
        };
        _crossTenantAuthService.ValidateCrossTenantAccessAsync("meshtest", "octosystem", userId)
            .Returns(crossTenantResult);

        // Provisioning FAILS
        _crossTenantUserProvisioningService
            .FindOrCreateCrossTenantUserAsync(crossTenantResult, "meshtest")
            .Returns((RtUser?)null);

        // Act
        var result = await _sut.Authorize(new DeviceAuthorizationRequestDto
        {
            UserCode = "valid-code"
        });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Failed to create local user");

        await _deviceInteraction.DidNotReceive()
            .HandleRequestAsync(Arg.Any<string>(), Arg.Any<ConsentResponse>());
    }

    [Fact]
    public async Task Authorize_WithCrossTenantUser_NoProviderConfigured_ReturnsAccessDenied()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));
        SetupDeviceInteractionReturnsContext("valid-code");

        _userManager.FindByIdAsync(userId).Returns((RtUser?)null);

        // No OctoTenantIdentityProviders configured
        _identityProviderStore.GetAllAsync()
            .Returns(Array.Empty<RtIdentityProvider>());

        // Act
        var result = await _sut.Authorize(new DeviceAuthorizationRequestDto
        {
            UserCode = "valid-code"
        });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Cross-tenant access denied");
    }

    [Fact]
    public async Task Authorize_WithCrossTenantUser_DisabledProviderSkipped()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));
        SetupDeviceInteractionReturnsContext("valid-code");

        _userManager.FindByIdAsync(userId).Returns((RtUser?)null);

        // Provider is disabled
        var disabledProvider = new RtOctoTenantIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            IsEnabled = false,
            ParentTenantId = "octosystem"
        };
        _identityProviderStore.GetAllAsync()
            .Returns(new RtIdentityProvider[] { disabledProvider });

        // Act
        var result = await _sut.Authorize(new DeviceAuthorizationRequestDto
        {
            UserCode = "valid-code"
        });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Cross-tenant access denied");

        // Disabled provider should not be checked
        await _crossTenantAuthService.DidNotReceive()
            .ValidateCrossTenantAccessAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    #endregion

    #region Deny

    [Fact]
    public async Task Deny_WithValidUserCode_Succeeds()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));
        SetupDeviceInteractionReturnsContext("valid-code");

        // Act
        var result = await _sut.Deny(new DeviceDenyRequestDto { UserCode = "valid-code" });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeTrue();
        await _deviceInteraction.Received(1).HandleRequestAsync("valid-code",
            Arg.Is<ConsentResponse>(c => c.Error == AuthorizationError.AccessDenied));
    }

    [Fact]
    public async Task Deny_WithInvalidUserCode_ReturnsFailure()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString("N");
        SetupControllerContext("meshtest", CreateAuthenticatedUser(userId));

        _deviceInteraction.GetAuthorizationContextAsync("invalid-code")
            .Returns((DeviceFlowAuthorizationRequest?)null);

        // Act
        var result = await _sut.Deny(new DeviceDenyRequestDto { UserCode = "invalid-code" });

        // Assert
        result.Value.Should().NotBeNull();
        result.Value!.Success.Should().BeFalse();
        result.Value.ErrorMessage.Should().Contain("Invalid or expired");
    }

    #endregion

    #region GetContext

    [Fact]
    public async Task GetContext_WithNullUserCode_ReturnsBadRequest()
    {
        // Arrange
        SetupControllerContext("meshtest");

        // Act
        var result = await _sut.GetContext(null);

        // Assert
        result.Result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task GetContext_WithInvalidUserCode_ReturnsNotFound()
    {
        // Arrange
        SetupControllerContext("meshtest");
        _deviceInteraction.GetAuthorizationContextAsync("bad-code")
            .Returns((DeviceFlowAuthorizationRequest?)null);

        // Act
        var result = await _sut.GetContext("bad-code");

        // Assert
        result.Result.Should().BeOfType<NotFoundObjectResult>();
    }

    #endregion
}
