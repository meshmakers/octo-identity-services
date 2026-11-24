using System.Diagnostics.Metrics;
using System.Security.Claims;
using System.Security.Cryptography;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Configuration;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Protocol;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Configuration;
using Meshmakers.Octo.Services.Infrastructure.TenantGeneration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Fakes;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.UnitTests.OpenIddict;

/// <summary>
///     AB#9017: identity refuses a token-exchange or on-behalf-of subject token and a refresh token, authorization code or
///     device code of an earlier tenant with the same id. The real evaluator of octo-common-services
///     (<see cref="TenantGenerationCheck" />, AB#8999) runs behind <see cref="GrantTenantGenerationGuard" />; only the
///     cached reader is faked. Per grant type: match, mismatch, missing (LogOnly vs Enforce), not checked, system tenant,
///     lookup failure; plus the processors with genuinely signed subject tokens and the metric labels.
/// </summary>
public class GrantTenantGenerationGuardTests
{
    private const string Tenant = "scratch-9017";
    private const string SystemTenant = "octosystem";
    private const string Current = "1794750381540";
    private const string Earlier = "1763193600123";
    private const string Authority = "https://identity.example.com";

    private readonly ITenantGenerationReader _reader = Substitute.For<ITenantGenerationReader>();
    private readonly RsaSecurityKey _signingKey = new(RSA.Create(2048)) { KeyId = "unit-test-key-9017" };

    public GrantTenantGenerationGuardTests()
    {
        _reader.GetGenerationAsync(Tenant, Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<string?>(Current));
    }

    public static TheoryData<string> GrantTypes =>
    [
        GrantTenantGenerationGrantTypes.TokenExchange, GrantTenantGenerationGrantTypes.OnBehalfOf,
        GrantTenantGenerationGrantTypes.RefreshToken, GrantTenantGenerationGrantTypes.AuthorizationCode,
        GrantTenantGenerationGrantTypes.DeviceCode
    ];

    // --- the decision matrix, per grant type ----------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(GrantTypes))]
    public async Task Match_IsAllowed_InEveryMode(string grantType)
    {
        foreach (var mode in new[] { TenantGenerationEnforcementMode.LogOnly, TenantGenerationEnforcementMode.Enforce })
        {
            var result = await Guard(mode).CheckAsync(Tenant, Gen(Current), grantType, "client-a", Ct);

            result.IsRefused.Should().BeFalse("mode {0}", mode);
            result.Outcome.Should().Be(TenantGenerationOutcome.Match);
        }
    }

    [Theory]
    [MemberData(nameof(GrantTypes))]
    public async Task Mismatch_IsInvalidGrant_InEnforce_AndAllowedInLogOnly(string grantType)
    {
        var enforced = await Guard(TenantGenerationEnforcementMode.Enforce)
            .CheckAsync(Tenant, Gen(Earlier), grantType, "client-a", Ct);
        var logged = await Guard(TenantGenerationEnforcementMode.LogOnly)
            .CheckAsync(Tenant, Gen(Earlier), grantType, "client-a", Ct);

        enforced.Error.Should().Be(Errors.InvalidGrant);
        enforced.ErrorDescription.Should().Be(GrantTenantGenerationGuard.RefusedDescription);
        enforced.ErrorDescription.Should().NotContain(Earlier).And.NotContain(Current).And.NotContain(Tenant);
        logged.IsRefused.Should().BeFalse("LogOnly never changes the outcome of a grant");
        logged.Outcome.Should().Be(TenantGenerationOutcome.Mismatch);
    }

    [Theory]
    [MemberData(nameof(GrantTypes))]
    public async Task Missing_IsInvalidGrant_InEnforce_AndAllowedInLogOnly(string grantType)
    {
        var enforced = await Guard(TenantGenerationEnforcementMode.Enforce)
            .CheckAsync(Tenant, null, grantType, "client-a", Ct);
        var logged = await Guard(TenantGenerationEnforcementMode.LogOnly)
            .CheckAsync(Tenant, null, grantType, "client-a", Ct);

        enforced.Error.Should().Be(Errors.InvalidGrant);
        logged.IsRefused.Should().BeFalse();
        logged.Outcome.Should().Be(TenantGenerationOutcome.Missing);
    }

    [Theory]
    [MemberData(nameof(GrantTypes))]
    public async Task TenantWithoutGeneration_IsNotChecked_AndAllowed(string grantType)
    {
        _reader.GetGenerationAsync("legacy", Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<string?>((string?)null));

        var result = await Guard(TenantGenerationEnforcementMode.Enforce)
            .CheckAsync("legacy", null, grantType, "client-a", Ct);

        result.IsRefused.Should().BeFalse();
        result.Outcome.Should().Be(TenantGenerationOutcome.NotChecked);
    }

    [Theory]
    [MemberData(nameof(GrantTypes))]
    public async Task SystemTenant_IsNeverRefused_NotEvenWithAForeignValue(string grantType)
    {
        var result = await Guard(TenantGenerationEnforcementMode.Enforce)
            .CheckAsync("OctoSystem", Gen(Earlier), grantType, "client-a", Ct);

        result.IsRefused.Should().BeFalse();
        result.Outcome.Should().Be(TenantGenerationOutcome.NotChecked);
        await _reader.DidNotReceiveWithAnyArgs().GetGenerationAsync(default!, default, TestContext.Current.CancellationToken);
    }

    [Theory]
    [MemberData(nameof(GrantTypes))]
    public async Task LookupFailure_IsServerError_InEnforce_AndAllowedInLogOnly(string grantType)
    {
        _reader.GetGenerationAsync("down", Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new TenantGenerationLookupException("down", new TimeoutException()));

        var enforced = await Guard(TenantGenerationEnforcementMode.Enforce)
            .CheckAsync("down", Gen(Current), grantType, "client-a", Ct);
        var logged = await Guard(TenantGenerationEnforcementMode.LogOnly)
            .CheckAsync("down", Gen(Current), grantType, "client-a", Ct);

        enforced.Error.Should().Be(Errors.ServerError);
        enforced.ErrorDescription.Should().Be(GrantTenantGenerationGuard.UnavailableDescription);
        logged.IsRefused.Should().BeFalse();
        logged.Outcome.Should().Be(TenantGenerationOutcome.LookupFailed);
    }

    [Fact]
    public async Task Disabled_LooksNothingUp_AndAllowsEverything()
    {
        var result = await Guard(TenantGenerationEnforcementMode.Disabled)
            .CheckAsync(Tenant, Gen(Earlier), GrantTenantGenerationGrantTypes.RefreshToken, "client-a", Ct);

        result.IsRefused.Should().BeFalse();
        await _reader.DidNotReceiveWithAnyArgs().GetGenerationAsync(default!, default, TestContext.Current.CancellationToken);
    }

    [Fact]
    public void TheDefaultResult_IsAnAllowedMatch()
    {
        // NSubstitute (and any default) answers an allowed check; the processors' existing tests rely on it.
        default(GrantTenantGenerationResult).IsRefused.Should().BeFalse();
    }

    // --- metric -----------------------------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(GrantTypes))]
    public async Task EveryCheck_IsCounted_WithTransportGrant_AndTheGrantType_NeverWithTenantOrValue(string grantType)
    {
        var clientId = $"client-{Guid.NewGuid():N}";
        var measurements = new List<IReadOnlyDictionary<string, object?>>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == TenantGenerationMetrics.MeterName &&
                instrument.Name == TenantGenerationMetrics.CounterName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            var dictionary = new Dictionary<string, object?>();
            foreach (var tag in tags)
            {
                dictionary[tag.Key] = tag.Value;
            }

            if (Equals(dictionary.GetValueOrDefault(TenantGenerationMetrics.ClientIdTag), clientId))
            {
                lock (measurements)
                {
                    measurements.Add(dictionary);
                }
            }
        });
        listener.Start();

        await Guard(TenantGenerationEnforcementMode.LogOnly).CheckAsync(Tenant, Gen(Earlier), grantType, clientId, Ct);

        var tags = measurements.Should().ContainSingle().Subject;
        tags[TenantGenerationMetrics.TransportTag].Should().Be(TenantGenerationTransports.Grant);
        tags[TenantGenerationMetrics.GrantTypeTag].Should().Be(grantType);
        tags[TenantGenerationMetrics.OutcomeTag].Should().Be("mismatch");
        tags.Keys.Should().BeEquivalentTo(TenantGenerationMetrics.OutcomeTag, TenantGenerationMetrics.ModeTag,
            TenantGenerationMetrics.TransportTag, TenantGenerationMetrics.ClientIdTag,
            TenantGenerationMetrics.GrantTypeTag);
        tags.Values.Should().NotContain(Tenant).And.NotContain(Earlier).And.NotContain(Current);
    }

    // --- token exchange --------------------------------------------------------------------------------------------

    [Fact]
    public async Task TokenExchange_SubjectTokenOfAnEarlierTenant_IsRefusedInEnforce_BeforeAnyShadowUserWork()
    {
        var (processor, crossTenant, provisioning) = CreateExchangeProcessor(TenantGenerationEnforcementMode.Enforce);

        var outcome = await processor.ProcessAsync(SubjectToken(Tenant, Earlier), AccessTokenType, "tenant:target", Ct);

        outcome.Error.Should().Be(Errors.InvalidGrant);
        outcome.ShadowUser.Should().BeNull();
        await crossTenant.DidNotReceiveWithAnyArgs().ValidateCrossTenantAccessAsync(default!, default!, default!);
        await provisioning.DidNotReceiveWithAnyArgs()
            .FindOrCreateCrossTenantUserAsync(default!, default!, default);
    }

    [Fact]
    public async Task TokenExchange_SubjectTokenWithoutGeneration_IsRefusedInEnforce()
    {
        var (processor, crossTenant, _) = CreateExchangeProcessor(TenantGenerationEnforcementMode.Enforce);

        var outcome = await processor.ProcessAsync(SubjectToken(Tenant, null), AccessTokenType, "tenant:target", Ct);

        outcome.Error.Should().Be(Errors.InvalidGrant);
        await crossTenant.DidNotReceiveWithAnyArgs().ValidateCrossTenantAccessAsync(default!, default!, default!);
    }

    [Theory]
    [InlineData(TenantGenerationEnforcementMode.LogOnly, Earlier)]
    [InlineData(TenantGenerationEnforcementMode.Enforce, Current)]
    public async Task TokenExchange_LogOnlyMismatch_OrAFreshToken_GoesOnToTheExchange(
        TenantGenerationEnforcementMode mode, string generation)
    {
        var (processor, crossTenant, _) = CreateExchangeProcessor(mode);

        var outcome = await processor.ProcessAsync(SubjectToken(Tenant, generation), AccessTokenType,
            "tenant:target", Ct);

        // The (faked) cross-tenant gate denies: the request reached the exchange itself.
        outcome.Error.Should().NotBe(Errors.InvalidGrant);
        await crossTenant.ReceivedWithAnyArgs().ValidateCrossTenantAccessAsync(default!, default!, default!);
    }

    [Fact]
    public async Task TokenExchange_ANumericTenantGen_IsAMismatch()
    {
        var (processor, _, _) = CreateExchangeProcessor(TenantGenerationEnforcementMode.Enforce);

        var outcome = await processor.ProcessAsync(SubjectToken(Tenant, long.Parse(Current)), AccessTokenType,
            "tenant:target", Ct);

        outcome.Error.Should().Be(Errors.InvalidGrant, "tenant_gen is a JSON string; a number is not well formed");
    }

    // --- on-behalf-of ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task OnBehalfOf_SubjectTokenOfAnEarlierTenant_IsRefusedInEnforce_BeforeRolesAreResolved()
    {
        var (processor, resolver, impersonation) = CreateOnBehalfOfProcessor(TenantGenerationEnforcementMode.Enforce);

        var plain = await processor.ProcessAsync("sa", null, SubjectToken(Tenant, Earlier), AccessTokenType,
            $"tenant:{Tenant}", ["openid"], Ct);
        var throughActor = await processor.ProcessAsync("actor", "sa", SubjectToken(Tenant, Earlier),
            AccessTokenType, $"tenant:{Tenant}", ["openid"], Ct);

        plain.Error.Should().Be(Errors.InvalidGrant);
        throughActor.Error.Should().Be(Errors.InvalidGrant, "the delegated variant follows the same rule");
        await resolver.DidNotReceiveWithAnyArgs().ResolveAsync(default!, default!, TestContext.Current.CancellationToken);
        await impersonation.DidNotReceiveWithAnyArgs().AuthorizeActorAsync(default!, default!, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData(TenantGenerationEnforcementMode.LogOnly, Earlier)]
    [InlineData(TenantGenerationEnforcementMode.LogOnly, null)]
    [InlineData(TenantGenerationEnforcementMode.Enforce, Current)]
    public async Task OnBehalfOf_LogOnly_OrAFreshToken_IsGranted(TenantGenerationEnforcementMode mode,
        string? generation)
    {
        var (processor, _, _) = CreateOnBehalfOfProcessor(mode);

        var outcome = await processor.ProcessAsync("sa", null, SubjectToken(Tenant, generation), AccessTokenType,
            $"tenant:{Tenant}", ["openid"], Ct);

        outcome.Error.Should().BeNull(outcome.ErrorDescription);
        outcome.UserSubjectId.Should().Be(UserId);
    }

    // --- stored grant claim and JWT bearer label ---------------------------------------------------------------------

    [Fact]
    public void StoredGrant_WithoutTheClaim_IsMissing_OneValue_IsRead_TwoValues_AreNotWellFormed()
    {
        TokenEndpointController.ReadStoredGeneration(Principal()).Should().Be(((TenantGenerationClaim?)null, (string?)null));

        var one = TokenEndpointController.ReadStoredGeneration(Principal(Current));
        one.RawValue.Should().Be(Current);
        one.Claim!.IsWellFormed.Should().BeTrue();

        var two = TokenEndpointController.ReadStoredGeneration(Principal(Current, Earlier));
        two.Claim!.IsWellFormed.Should().BeFalse();
        two.RawValue.Should().BeNull();
    }

    [Fact]
    public void JwtBearer_LabelsTheIdentityBearer_SoTheTenantAuthorizationMiddlewareChecksIt()
    {
        var environment = Substitute.For<IWebHostEnvironment>();
        environment.EnvironmentName.Returns(Environments.Production);
        var options = new JwtBearerOptions();

        new ConfigureJwtBearerOptions(Options.Create(new OctoIdentityServicesOptions { AuthorityUrl = Authority }),
            environment).Configure(JwtBearerDefaults.AuthenticationScheme, options);

        // TenantAuthorizationMiddleware skips every principal whose AuthenticationType is not "Bearer"; the framework
        // default "AuthenticationTypes.Federation" made identity's HTTP tenant check a no-op for bearer tokens.
        options.TokenValidationParameters.AuthenticationType.Should().Be("Bearer");
        var identity = new ClaimsIdentity([new Claim("sub", "u")],
            options.TokenValidationParameters.AuthenticationType);
        identity.AuthenticationType.Should().Be("Bearer");
    }

    // --- helpers ----------------------------------------------------------------------------------------------------

    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
    private const string UserId = "68b0000000000000000000a1";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static TenantGenerationClaim Gen(string value) => TenantGenerationClaim.FromValue(value);

    private GrantTenantGenerationGuard Guard(TenantGenerationEnforcementMode mode)
    {
        var check = new TenantGenerationCheck(_reader, new TenantGenerationMetrics(),
            Options.Create(new TenantAuthorizationOptions { TenantGenerationEnforcement = mode }),
            Options.Create(new OctoSystemConfiguration { SystemTenantId = SystemTenant }),
            NullLogger<TenantGenerationCheck>.Instance);
        return new GrantTenantGenerationGuard(check);
    }

    private IOptionsMonitor<OpenIddictServerOptions> ServerOptions()
    {
        var serverOptions = Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>();
        var options = new OpenIddictServerOptions();
        options.SigningCredentials.Add(new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256));
        serverOptions.CurrentValue.Returns(options);
        return serverOptions;
    }

    private static IHttpContextAccessor WiredTo(string tenantId)
    {
        var accessor = Substitute.For<IHttpContextAccessor>();
        var httpContext = new DefaultHttpContext();
        httpContext.Items[InfrastructureCommon.TenantIdName] = tenantId;
        accessor.HttpContext.Returns(httpContext);
        return accessor;
    }

    private (TenantExchangeProcessor Processor, ICrossTenantAuthenticationService CrossTenant,
        ICrossTenantUserProvisioningService Provisioning) CreateExchangeProcessor(TenantGenerationEnforcementMode mode)
    {
        var crossTenant = Substitute.For<ICrossTenantAuthenticationService>();
        var provisioning = Substitute.For<ICrossTenantUserProvisioningService>();
        var processor = new TenantExchangeProcessor(
            ServerOptions(),
            Options.Create(new OctoIdentityServicesOptions { AuthorityUrl = Authority }),
            crossTenant,
            provisioning,
            new RegisteredTenantsShadowUserChainResolver(Tenant),
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
            WiredTo("target"),
            Substitute.For<IIdentityAuditService>(),
            Substitute.For<Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit.ICrossTenantGrantAuditRecorder>(),
            Guard(mode),
            Substitute.For<IdentityServerPersistence.Services.ServiceAccountExchange.IServiceAccountExchangeGate>(),
            NullLogger<TenantExchangeProcessor>.Instance);
        return (processor, crossTenant, provisioning);
    }

    private (OnBehalfOfProcessor Processor, IDelegatedIdentityResolver Resolver,
        IImpersonatedIdentityResolver Impersonation) CreateOnBehalfOfProcessor(TenantGenerationEnforcementMode mode)
    {
        var resolver = Substitute.For<IDelegatedIdentityResolver>();
        resolver.ResolveAsync("sa", UserId, Arg.Any<CancellationToken>())
            .Returns(DelegatedIdentityResult.Granted(Roles("Reader"), Roles("Reader"), Roles("Reader")));
        var impersonation = Substitute.For<IImpersonatedIdentityResolver>();
        var processor = new OnBehalfOfProcessor(
            ServerOptions(),
            Options.Create(new OctoIdentityServicesOptions { AuthorityUrl = Authority }),
            resolver,
            impersonation,
            WiredTo(Tenant),
            Substitute.For<IIdentityAuditService>(),
            Guard(mode),
            NullLogger<OnBehalfOfProcessor>.Instance);
        return (processor, resolver, impersonation);
    }

    private static IReadOnlySet<string> Roles(params string[] roles) =>
        new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);

    /// <summary>A genuinely signed access token (typ at+jwt) with <c>tenant_gen</c> as given (string, number or none).</summary>
    private string SubjectToken(string tenantId, object? generation)
    {
        var claims = new Dictionary<string, object>
        {
            [Claims.Subject] = UserId,
            ["tenant_id"] = tenantId,
            [Claims.ClientId] = "client-a"
        };
        if (generation != null)
        {
            claims[TenantGenerationClaim.ClaimType] = generation;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            TokenType = "at+jwt",
            Issuer = Authority.EnsureEndsWith("/"),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
            Claims = claims
        });
    }

    private static ClaimsPrincipal Principal(params string[] storedGenerations)
    {
        var identity = new ClaimsIdentity("test");
        foreach (var value in storedGenerations)
        {
            identity.AddClaim(new Claim(OctoClaimTypes.GrantTenantGeneration, value));
        }

        return new ClaimsPrincipal(identity);
    }
}
