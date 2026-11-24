using System.Security.Cryptography;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.ServiceAccountExchange;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.TenantGeneration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Fakes;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#9777 — the RFC 8693 exchange accepts a service-account (client-credentials) token of T as subject: the
///     protocol half of <see cref="TenantExchangeProcessor" /> with genuinely signed subject tokens. The authorization
///     itself (relation, mirror, provisioning in U, allow-list) is <see cref="IServiceAccountExchangeGate" />, faked here
///     and covered against MongoDB by <c>ServiceAccountExchangeGateIntegrationTests</c>.
/// </summary>
public class TenantExchangeServiceAccountSubjectTests
{
    private const string Authority = "https://identity.example.com/";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
    private const string Source = "acme-a";
    private const string Target = "acme-g";
    private const string ClientId = "octo-pipeline-sa-0001";
    private const string ShadowClientId = "xt_acme-a_octo-pipeline-sa-0001";

    private readonly RsaSecurityKey _signingKey = new(RSA.Create(2048)) { KeyId = "unit-test-key-9777" };
    private readonly IServiceAccountExchangeGate _gate = Substitute.For<IServiceAccountExchangeGate>();
    private readonly ICrossTenantAuthenticationService _crossTenant = Substitute.For<ICrossTenantAuthenticationService>();
    private readonly IIdentityAuditService _audit = Substitute.For<IIdentityAuditService>();
    private readonly ICrossTenantGrantAuditRecorder _grantAudit = Substitute.For<ICrossTenantGrantAuditRecorder>();
    private readonly IGrantTenantGenerationGuard _generationGuard = Substitute.For<IGrantTenantGenerationGuard>();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ServiceAccountSubject_Admitted_YieldsTheShadowClientWithItsTargetRoles()
    {
        var shadow = new RtClient { RtId = OctoObjectId.GenerateNewId(), ClientId = ShadowClientId, Enabled = true };
        _gate.EvaluateAsync(Source, ClientId, Target).Returns(new ServiceAccountExchangeDecision
        {
            Refusal = ServiceAccountExchangeRefusal.None,
            Relation = ServiceAccountExchangeRelation.Parent,
            ShadowClient = shadow,
            RoleNames = new HashSet<string> { "TargetReader" }
        });

        var outcome = await CreateSut().ProcessAsync(ServiceToken(), AccessTokenType, $"tenant:{Target}", Ct,
            ShadowClientId);

        outcome.Error.Should().BeNull();
        outcome.ShadowUser.Should().BeNull("a service subject never becomes a user");
        outcome.ShadowClient.Should().BeSameAs(shadow);
        outcome.ShadowClientRoleNames.Should().BeEquivalentTo(["TargetReader"]);
        outcome.TargetTenantId.Should().Be(Target);
        outcome.SourceTenantId.Should().Be(Source);
        outcome.SourceClientId.Should().Be(ClientId);
        await _crossTenant.DidNotReceiveWithAnyArgs().ValidateCrossTenantAccessAsync(default!, default!, default!);
    }

    [Fact]
    public async Task ServiceAccountSubject_PresentedByAnotherClient_IsUnauthorizedClient_AndAudited()
    {
        _gate.EvaluateAsync(Source, ClientId, Target).Returns(new ServiceAccountExchangeDecision
        {
            Refusal = ServiceAccountExchangeRefusal.None,
            ShadowClient = new RtClient { RtId = OctoObjectId.GenerateNewId(), ClientId = ShadowClientId },
            RoleNames = new HashSet<string> { "TargetReader" }
        });

        var outcome = await CreateSut().ProcessAsync(ServiceToken(), AccessTokenType, $"tenant:{Target}", Ct,
            "octo-cli");

        outcome.Error.Should().Be(Errors.UnauthorizedClient);
        outcome.ShadowClient.Should().BeNull();
        await _grantAudit.Received(1).RecordExchangeRefusedAsync(Target, Source, ClientId, Arg.Any<string>());
    }

    [Theory]
    [InlineData(ServiceAccountExchangeRefusal.NotProvisioned, "access_denied", TenantExchangeProcessor.NotProvisionedMarker)]
    [InlineData(ServiceAccountExchangeRefusal.MirroredClient, "access_denied", TenantExchangeProcessor.MirroredClientMarker)]
    [InlineData(ServiceAccountExchangeRefusal.NotPermitted, "access_denied", TenantExchangeProcessor.GrantNotPermittedMarker)]
    [InlineData(ServiceAccountExchangeRefusal.AmbiguousSubject, "access_denied", TenantExchangeProcessor.AmbiguousSubjectMarker)]
    [InlineData(ServiceAccountExchangeRefusal.ShadowClientNotExchangeOnly, "access_denied", TenantExchangeProcessor.ShadowClientInvalidMarker)]
    [InlineData(ServiceAccountExchangeRefusal.NotRelated, "unauthorized_client", "cross-tenant access")]
    [InlineData(ServiceAccountExchangeRefusal.SystemTenant, "unauthorized_client", "cross-tenant access")]
    [InlineData(ServiceAccountExchangeRefusal.UnknownTenant, "unauthorized_client", "cross-tenant access")]
    [InlineData(ServiceAccountExchangeRefusal.SourceClientUnknown, "invalid_grant", "the subject service account")]
    [InlineData(ServiceAccountExchangeRefusal.StateUnreadable, "access_denied", "the service-account exchange could not be checked")]
    public async Task ServiceAccountSubject_RefusedByTheGate_MapsToAStableError_AndRaisesTheAudit(
        ServiceAccountExchangeRefusal refusal, string error, string descriptionPrefix)
    {
        _gate.EvaluateAsync(Source, ClientId, Target)
            .Returns(ServiceAccountExchangeDecision.Refused(refusal, "test reason"));

        var outcome = await CreateSut().ProcessAsync(ServiceToken(), AccessTokenType, $"tenant:{Target}", Ct,
            ShadowClientId);

        outcome.Error.Should().Be(error);
        outcome.ErrorDescription.Should().StartWith(descriptionPrefix);
        outcome.ShadowClient.Should().BeNull();
        await _audit.Received(1).StoreFailureAsync("Token Exchange Failure", Arg.Is<string>(m => m.Contains(ClientId)));
        await _grantAudit.Received(1).RecordExchangeRefusedAsync(Target, Source, ClientId, Arg.Any<string>());
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("foreign-key")]
    [InlineData("foreign-issuer")]
    public async Task ServiceAccountSubject_NotAValidTokenOfThisIdentity_IsRefusedBeforeTheGate(string kind)
    {
        var token = kind switch
        {
            "expired" => CreateToken(ServiceClaims(), expires: DateTime.UtcNow.AddMinutes(-10)),
            "foreign-key" => CreateToken(ServiceClaims(), key: new RsaSecurityKey(RSA.Create(2048)) { KeyId = "other" }),
            _ => CreateToken(ServiceClaims(), issuer: "https://other-identity.example.com/")
        };

        var outcome = await CreateSut().ProcessAsync(token, AccessTokenType, $"tenant:{Target}", Ct, ShadowClientId);

        outcome.Error.Should().Be(Errors.InvalidGrant);
        await _gate.DidNotReceiveWithAnyArgs().EvaluateAsync(default!, default!, default!);
    }

    [Fact]
    public async Task ServiceAccountSubject_PresenterDiffersOnlyInCase_IsUnauthorizedClient()
    {
        _gate.EvaluateAsync(Source, ClientId, Target).Returns(new ServiceAccountExchangeDecision
        {
            Refusal = ServiceAccountExchangeRefusal.None,
            ShadowClient = new RtClient { RtId = OctoObjectId.GenerateNewId(), ClientId = ShadowClientId },
            RoleNames = new HashSet<string> { "TargetReader" }
        });

        var outcome = await CreateSut().ProcessAsync(ServiceToken(), AccessTokenType, $"tenant:{Target}", Ct,
            ShadowClientId.ToUpperInvariant());

        outcome.Error.Should().Be(Errors.UnauthorizedClient);
    }

    [Fact]
    public async Task ServiceAccountSubject_CarryingAct_IsRefusedBeforeTheGate()
    {
        var outcome = await CreateSut().ProcessAsync(ServiceToken(extra: new Dictionary<string, object>
        {
            ["act"] = "some-actor"
        }), AccessTokenType, $"tenant:{Target}", Ct, ShadowClientId);

        outcome.Error.Should().Be(Errors.InvalidGrant);
        await _gate.DidNotReceiveWithAnyArgs().EvaluateAsync(default!, default!, default!);
    }

    [Fact]
    public async Task ServiceAccountSubject_OfAnEarlierTenantGeneration_IsRefusedBeforeTheGate()
    {
        _generationGuard.CheckAsync(Source, Arg.Any<TenantGenerationClaim?>(), GrantTenantGenerationGrantTypes.TokenExchange,
                ClientId, Arg.Any<CancellationToken>())
            .Returns(new ValueTask<GrantTenantGenerationResult>(new GrantTenantGenerationResult(
                TenantGenerationOutcome.Mismatch, Errors.InvalidGrant, GrantTenantGenerationGuard.RefusedDescription)));

        var outcome = await CreateSut().ProcessAsync(ServiceToken(), AccessTokenType, $"tenant:{Target}", Ct,
            ShadowClientId);

        outcome.Error.Should().Be(Errors.InvalidGrant);
        outcome.ErrorDescription.Should().Be(GrantTenantGenerationGuard.RefusedDescription);
        await _gate.DidNotReceiveWithAnyArgs().EvaluateAsync(default!, default!, default!);
    }

    [Fact]
    public async Task ServiceAccountSubject_TargetNotWiredIntoTheRequest_IsInvalidTarget()
    {
        var outcome = await CreateSut(wiredTenant: "elsewhere").ProcessAsync(ServiceToken(), AccessTokenType,
            $"tenant:{Target}", Ct, ShadowClientId);

        outcome.Error.Should().Be(Errors.InvalidTarget);
        await _gate.DidNotReceiveWithAnyArgs().EvaluateAsync(default!, default!, default!);
    }

    [Fact]
    public async Task SubjectWithoutSubAndWithoutClientId_IsStillRefusedAsBefore()
    {
        var token = CreateToken(new Dictionary<string, object> { ["tenant_id"] = Source });

        var outcome = await CreateSut().ProcessAsync(token, AccessTokenType, $"tenant:{Target}", Ct, ShadowClientId);

        outcome.Error.Should().Be(Errors.InvalidGrant);
        outcome.ErrorDescription.Should().Contain("user subject");
        await _gate.DidNotReceiveWithAnyArgs().EvaluateAsync(default!, default!, default!);
    }

    [Fact]
    public async Task UserSubject_NeverReachesTheServiceAccountGate()
    {
        var token = CreateToken(new Dictionary<string, object>
        {
            [Claims.Subject] = "68b0000000000000000000a1", ["tenant_id"] = Source, [Claims.ClientId] = "octo-cli"
        });

        await CreateSut().ProcessAsync(token, AccessTokenType, $"tenant:{Target}", Ct, "octo-cli");

        await _gate.DidNotReceiveWithAnyArgs().EvaluateAsync(default!, default!, default!);
        await _crossTenant.ReceivedWithAnyArgs().ValidateCrossTenantAccessAsync(default!, default!, default!);
    }

    private TenantExchangeProcessor CreateSut(string wiredTenant = Target)
    {
        var serverOptions = Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>();
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256));
        serverOptions.CurrentValue.Returns(options);

        var accessor = Substitute.For<IHttpContextAccessor>();
        var httpContext = new DefaultHttpContext();
        httpContext.Items[InfrastructureCommon.TenantIdName] = wiredTenant;
        accessor.HttpContext.Returns(httpContext);

        return new TenantExchangeProcessor(
            serverOptions,
            Options.Create(new OctoIdentityServicesOptions { AuthorityUrl = Authority }),
            _crossTenant,
            Substitute.For<ICrossTenantUserProvisioningService>(),
            new RegisteredTenantsShadowUserChainResolver(Source),
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
            accessor,
            _audit,
            _grantAudit,
            _generationGuard,
            _gate,
            NullLogger<TenantExchangeProcessor>.Instance);
    }

    /// <summary>A client_credentials-shaped access token of T: client_id and tenant_id, no sub.</summary>
    private string ServiceToken(Dictionary<string, object>? extra = null)
    {
        var claims = ServiceClaims();
        foreach (var (key, value) in extra ?? [])
        {
            claims[key] = value;
        }

        return CreateToken(claims);
    }

    private static Dictionary<string, object> ServiceClaims() =>
        new() { [Claims.ClientId] = ClientId, ["tenant_id"] = Source };

    private string CreateToken(Dictionary<string, object> claims, DateTime? expires = null,
        SecurityKey? key = null, string? issuer = null)
    {
        var expiry = expires ?? DateTime.UtcNow.AddMinutes(5);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            TokenType = "at+jwt",
            Issuer = issuer ?? Authority.EnsureEndsWith("/"),
            NotBefore = expiry.AddMinutes(-15),
            IssuedAt = expiry.AddMinutes(-15),
            Expires = expiry,
            SigningCredentials = new SigningCredentials(key ?? _signingKey, SecurityAlgorithms.RsaSha256),
            Claims = claims
        });
    }
}
