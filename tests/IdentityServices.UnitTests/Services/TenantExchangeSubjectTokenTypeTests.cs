using System.Security.Cryptography;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#7860 — the token exchange accepts only an access token (<c>typ: at+jwt</c>) as <c>subject_token</c>.
/// </summary>
/// <remarks>
///     Over HTTP OpenIddict already refuses a non-access token for the RFC 8693 grant
///     (<c>CrossTenantSecondFactorTests.TokenExchange_IdTokenAsSubjectToken_IsRefused</c>); these tests pin the
///     processor's own check, which must not rely on that.
/// </remarks>
public class TenantExchangeSubjectTokenTypeTests
{
    private const string Authority = "https://identity.example.com/";
    private readonly RsaSecurityKey _signingKey = new(RSA.Create(2048)) { KeyId = "unit-test-key" };
    private readonly TenantExchangeProcessor _sut;

    public TenantExchangeSubjectTokenTypeTests()
    {
        var serverOptions = Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>();
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256));
        serverOptions.CurrentValue.Returns(options);

        _sut = new TenantExchangeProcessor(
            serverOptions,
            Options.Create(new OctoIdentityServicesOptions { AuthorityUrl = Authority }),
            Substitute.For<ICrossTenantAuthenticationService>(),
            Substitute.For<ICrossTenantUserProvisioningService>(),
            new RegisteredTenantsShadowUserChainResolver("source"),
            Substitute.For<IExternalTenantUserMappingStore>(),
            Substitute.For<UserManager<RtUser>>(
                Substitute.For<IUserStore<RtUser>>(),
                Substitute.For<IOptions<IdentityOptions>>(),
                Substitute.For<IPasswordHasher<RtUser>>(),
                Array.Empty<IUserValidator<RtUser>>(),
                Array.Empty<IPasswordValidator<RtUser>>(),
                Substitute.For<ILookupNormalizer>(),
                Substitute.For<IdentityErrorDescriber>(),
                Substitute.For<IServiceProvider>(),
                Substitute.For<ILogger<UserManager<RtUser>>>()),
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IIdentityAuditService>(),
            Substitute.For<ILogger<TenantExchangeProcessor>>());
    }

    [Theory]
    [InlineData("JWT")]
    [InlineData("logout+jwt")]
    public async Task SubjectTokenThatIsNoAccessToken_IsRejectedAsInvalidGrant(string tokenType)
    {
        var outcome = await _sut.ProcessAsync(CreateToken(tokenType), AccessTokenType, "tenant:child",
            TestContext.Current.CancellationToken);

        outcome.Error.Should().Be(Errors.InvalidGrant, "an id_token carries the same sub and tenant_id");
    }

    [Theory]
    [InlineData("at+jwt")]
    [InlineData("application/at+jwt")]
    public async Task AccessToken_PassesTheSubjectTokenValidation(string tokenType)
    {
        // No acr_values: the request fails at the NEXT step, which proves the subject token itself was accepted.
        var outcome = await _sut.ProcessAsync(CreateToken(tokenType), AccessTokenType, null,
            TestContext.Current.CancellationToken);

        outcome.Error.Should().Be(Errors.InvalidRequest);
        outcome.ErrorDescription.Should().Contain("acr_values");
    }

    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    private string CreateToken(string tokenType) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            TokenType = tokenType,
            Issuer = Authority.EnsureEndsWith("/"),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object>
            {
                [Claims.Subject] = "68b0000000000000000000a1",
                ["tenant_id"] = "source"
            }
        });
}
