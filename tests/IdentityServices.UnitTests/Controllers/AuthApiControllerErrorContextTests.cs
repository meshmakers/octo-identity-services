using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.Login;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.Services;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;
using Meshmakers.Octo.ConstructionKit.Contracts;
using OpenIddict.Abstractions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
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

/// <summary>
///     Covers the error-context endpoint that turns IdentityServer's opaque <c>errorId</c> into
///     something the error page can render, including the deliberate limits on the back-link.
/// </summary>
public class AuthApiControllerErrorContextTests
{
    private const string TenantId = "tecob";

    private readonly IOctoInteractionService _interaction;
    private readonly IOctoClientStore _clientStore;
    private readonly AuthApiController _sut;

    public AuthApiControllerErrorContextTests()
    {
        _interaction = Substitute.For<IOctoInteractionService>();
        _clientStore = Substitute.For<IOctoClientStore>();

        var userStore = Substitute.For<IUserStore<RtUser>>();
        var userManager = Substitute.For<UserManager<RtUser>>(
            userStore,
            Substitute.For<IOptions<IdentityOptions>>(),
            Substitute.For<IPasswordHasher<RtUser>>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            Substitute.For<ILookupNormalizer>(),
            Substitute.For<IdentityErrorDescriber>(),
            Substitute.For<IServiceProvider>(),
            Substitute.For<ILogger<UserManager<RtUser>>>());

        var signInManager = Substitute.For<SignInManager<RtUser>>(
            userManager,
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IUserClaimsPrincipalFactory<RtUser>>(),
            Substitute.For<IOptions<IdentityOptions>>(),
            Substitute.For<ILogger<SignInManager<RtUser>>>(),
            Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>(),
            Substitute.For<IUserConfirmation<RtUser>>());

        _sut = new AuthApiController(
            _interaction,
            Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>(),
            _clientStore,
            signInManager,
            userManager,
            Substitute.For<IIdentityAuditService>(),
            Substitute.For<IOpenIddictTokenStore<RtOAuthToken>>(),
            Substitute.For<ILdapAuthenticationService>(),
            Substitute.For<ICrossTenantAuthenticationService>(),
            Substitute.For<IExternalTenantUserMappingStore>(),
            Substitute.For<IOctoIdentityProviderStore>(),
            Substitute.For<ILoginGroupAssignmentService>(),
            new EphemeralDataProtectionProvider(),
            Substitute.For<ICrossTenantUserProvisioningService>(),
            Options.Create(new OctoSystemConfiguration { SystemTenantId = "OctoSystem" }),
            Substitute.For<ILogger<AuthApiController>>());

        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext(),
            RouteData = new RouteData(new RouteValueDictionary { { "tenantId", TenantId } })
        };
    }

    private static RtClient NewClient(Action<RtClient> configure)
    {
        var client = new RtClient
        {
            RtId = OctoObjectId.GenerateNewId(),
            ClientId = "meshmakers-app",
            Enabled = true
        };
        configure(client);
        return client;
    }

    private async Task<ErrorContextDto> GetContextAsync(string? errorId)
    {
        var result = await _sut.GetErrorContext(errorId);
        return result.Value!;
    }

    [Fact]
    public async Task GetErrorContext_WithoutErrorId_ReportsUnknownAndDoesNotTouchTheClientStore()
    {
        var context = await GetContextAsync(null);

        context.Kind.Should().Be(ErrorContextKinds.Unknown);
        context.TenantId.Should().Be(TenantId);
        await _clientStore.DidNotReceiveWithAnyArgs().FindRtClientByIdAsync(default!);
    }

    [Fact]
    public async Task GetErrorContext_WithExpiredErrorId_ReportsUnknown()
    {
        // An id the message store no longer knows resolves to null; the page still has to render.
        _interaction.GetErrorContext("stale").Returns((OctoErrorContext?)null);

        var context = await GetContextAsync("stale");

        context.Kind.Should().Be(ErrorContextKinds.Unknown);
    }

    [Fact]
    public async Task GetErrorContext_WhenClientIsUnknownInThisTenant_ReportsConfigurationStateWithoutBackLink()
    {
        _interaction.GetErrorContext("id")
            .Returns(new OctoErrorContext
            {
                Error = "unauthorized_client",
                ErrorDescription = "Unknown client or client not enabled",
                ClientId = "meshmakers-app",
                RequestId = "req-1"
            });
        _clientStore.FindRtClientByIdAsync("meshmakers-app")
            .Returns((RtClient?)null);

        var context = await GetContextAsync("id");

        context.Kind.Should().Be(ErrorContextKinds.ClientNotRegistered);
        context.ClientId.Should().Be("meshmakers-app");
        // Nothing trustworthy to link to when the client is not registered here.
        context.ClientUrl.Should().BeNull();
        context.RequestId.Should().Be("req-1");
    }

    [Fact]
    public async Task GetErrorContext_WithInvalidRedirectUri_NamesTheClientAndOffersItsRegisteredUri()
    {
        _interaction.GetErrorContext("id")
            .Returns(new OctoErrorContext
            {
                Error = "invalid_request",
                ErrorDescription = "Invalid redirect_uri",
                ClientId = "meshmakers-app"
            });
        _clientStore.FindRtClientByIdAsync("meshmakers-app")
            .Returns(NewClient(c =>
            {
                c.ClientName = "Accounting";
                c.ClientUri = "https://accounting.meshmakers.cloud/";
                c.LogoUri = "https://accounting.meshmakers.cloud/logo.svg";
            }));

        var context = await GetContextAsync("id");

        context.Kind.Should().Be(ErrorContextKinds.InvalidRedirectUri);
        context.ClientName.Should().Be("Accounting");
        context.ClientUrl.Should().Be("https://accounting.meshmakers.cloud/");
        context.ClientLogoUrl.Should().Be("https://accounting.meshmakers.cloud/logo.svg");
    }

    [Fact]
    public async Task GetErrorContext_WhenClientHasNoRegisteredUri_OffersNoBackLink()
    {
        _interaction.GetErrorContext("id")
            .Returns(new OctoErrorContext
            {
                Error = "invalid_request",
                ErrorDescription = "Invalid redirect_uri",
                ClientId = "meshmakers-app"
            });
        _clientStore.FindRtClientByIdAsync("meshmakers-app")
            .Returns(NewClient(c => c.ClientName = "Accounting"));

        var context = await GetContextAsync("id");

        context.ClientUrl.Should().BeNull();
    }

    [Fact]
    public async Task GetErrorContext_ForAnUnrelatedFailure_StaysGeneric()
    {
        // unauthorized_client is emitted for more than the unknown-client case, so the
        // classification must come from the store lookup, not from the description text.
        _interaction.GetErrorContext("id")
            .Returns(new OctoErrorContext
            {
                Error = "unauthorized_client",
                ErrorDescription = "Invalid protocol",
                ClientId = "meshmakers-app"
            });
        _clientStore.FindRtClientByIdAsync("meshmakers-app")
            .Returns(NewClient(c => c.ClientName = "Accounting"));

        var context = await GetContextAsync("id");

        context.Kind.Should().Be(ErrorContextKinds.Generic);
    }

    [Fact]
    public async Task GetErrorContext_WhenClientIsRegisteredButDisabled_ReadsAsNotRegistered()
    {
        // The error-context lookup filters on Enabled, so a disabled client is
        // indistinguishable from a missing one here — which is exactly why the copy
        // says "not registered, or not enabled".
        _interaction.GetErrorContext("id")
            .Returns(new OctoErrorContext
            {
                Error = "unauthorized_client",
                ErrorDescription = "Unknown client or client not enabled",
                ClientId = "meshmakers-app"
            });
        _clientStore.FindRtClientByIdAsync("meshmakers-app")
            .Returns(NewClient(c =>
            {
                c.ClientName = "Accounting";
                c.ClientUri = "https://accounting.meshmakers.cloud/";
                c.Enabled = false;
            }));

        var context = await GetContextAsync("id");

        context.Kind.Should().Be(ErrorContextKinds.ClientNotRegistered);
        // A disabled client must not be offered as a destination either.
        context.ClientUrl.Should().BeNull();
    }
}
