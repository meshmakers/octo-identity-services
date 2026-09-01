using System.Collections.Specialized;
using System.Security.Cryptography;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityModel;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5026 — protocol-level behaviour of the delegation ("on-behalf-of") grant, driven through a
///     real <see cref="ExtensionGrantValidationContext" /> and a genuinely signed
///     <c>subject_token</c>.
/// </summary>
/// <remarks>
///     <para>
///         The focus here is the <b>refresh-token prohibition</b>. The role intersection is computed
///         at issuance; a <c>grant_type=refresh_token</c> request rebuilds the access token from the
///         persisted grant without ever re-entering this validator, so the intersection would freeze
///         and a role revoked on either side (service account or user) would keep working for the
///         refresh token's whole lifetime. The grant therefore refuses <c>offline_access</c> outright
///         instead of merely documenting the hazard.
///     </para>
///     <para>
///         The intersection arithmetic itself is pinned by <see cref="DelegatedIdentityResolverTests" />
///         and the claim composition by <see cref="DelegationClaimCompositionTests" />; this class
///         only exercises the protocol adapter.
///     </para>
/// </remarks>
public class OnBehalfOfGrantValidatorTests
{
    private const string Authority = "https://identity.example.com";
    private const string TenantId = "acme";
    private const string ServiceAccountClientId = "octo-pipeline-sa";
    private const string UserSubjectId = "68b0000000000000000000a1";

    private readonly IEventService _events = Substitute.For<IEventService>();
    private readonly IHttpContextAccessor _httpContextAccessor = Substitute.For<IHttpContextAccessor>();
    private readonly IDelegatedIdentityResolver _resolver = Substitute.For<IDelegatedIdentityResolver>();
    private readonly RsaSecurityKey _signingKey = new(RSA.Create(2048)) { KeyId = "unit-test-key" };
    private readonly OnBehalfOfGrantValidator _sut;
    private readonly IValidationKeysStore _validationKeysStore = Substitute.For<IValidationKeysStore>();

    public OnBehalfOfGrantValidatorTests()
    {
        IReadOnlyCollection<SecurityKeyInfo> validationKeys =
        [
            new SecurityKeyInfo { Key = _signingKey, SigningAlgorithm = SecurityAlgorithms.RsaSha256 }
        ];
        _validationKeysStore.GetValidationKeysAsync(Arg.Any<CancellationToken>()).Returns(validationKeys);

        var httpContext = new DefaultHttpContext();
        httpContext.Items[InfrastructureCommon.TenantIdName] = TenantId;
        _httpContextAccessor.HttpContext.Returns(httpContext);

        _resolver.ResolveAsync(ServiceAccountClientId, UserSubjectId, Arg.Any<CancellationToken>())
            .Returns(DelegatedIdentityResult.Granted(
                RoleSet("AssetReader"), RoleSet("AssetReader", "PipelineOperator"),
                RoleSet("AssetReader", "TenantAdministrator")));

        _sut = new OnBehalfOfGrantValidator(
            _validationKeysStore,
            Options.Create(new OctoIdentityServicesOptions
            {
                AuthorityUrl = Authority,
                IdentityServerLicenseKey = string.Empty,
                AutoMapperLicenseKey = string.Empty
            }),
            _resolver,
            _httpContextAccessor,
            _events,
            NullLogger<OnBehalfOfGrantValidator>.Instance);
    }

    /// <summary>
    ///     THE regression this hardening exists for: a delegating client that asks for a refresh
    ///     token must be refused, not quietly served a token whose role intersection can never be
    ///     re-evaluated.
    /// </summary>
    [Fact]
    public async Task OfflineAccessRequested_IsRejectedAsInvalidScope()
    {
        var context = ValidationContext(scope: "openid octo_api offline_access");

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result.IsError.Should().BeTrue();
        context.Result.Error.Should().Be(OidcConstants.TokenErrors.InvalidScope);
    }

    /// <summary>
    ///     The error has to say <b>why</b>, otherwise an integrator hitting it has no path from
    ///     "invalid_scope" to "delegated tokens are not refreshable by design".
    /// </summary>
    [Fact]
    public async Task OfflineAccessRejection_ExplainsThatTheIntersectionCannotBeReEvaluated()
    {
        var context = ValidationContext(scope: "offline_access");

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result.ErrorDescription.Should().Contain("offline_access");
        context.Result.ErrorDescription.Should().Contain("intersection");
        context.Result.ErrorDescription.Should().ContainEquivalentOf("refresh");
    }

    [Fact]
    public async Task OfflineAccessRejection_RaisesADelegationFailureEvent()
    {
        var context = ValidationContext(scope: "openid offline_access");

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        await _events.Received(1).RaiseAsync(
            Arg.Is<DelegationFailureEvent>(e =>
                e.ActorClientId == ServiceAccountClientId &&
                e.TenantId == TenantId &&
                e.Reason.Contains("offline_access")),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    ///     A structurally impossible request is refused before any cryptography or database work —
    ///     and, more importantly, before anything reads the unvalidated <c>subject_token</c>.
    /// </summary>
    [Fact]
    public async Task OfflineAccessRejection_HappensBeforeTheSubjectTokenIsValidatedOrRolesResolved()
    {
        var context = ValidationContext(scope: "offline_access");

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        await _validationKeysStore.DidNotReceive().GetValidationKeysAsync(Arg.Any<CancellationToken>());
        await _resolver.DidNotReceive().ResolveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    ///     Duende decides to mint a refresh token from <c>ValidatedResources.Resources.OfflineAccess</c>.
    ///     Should that flag ever be set from somewhere other than the raw scope parameter, the grant
    ///     must still refuse.
    /// </summary>
    [Fact]
    public async Task OfflineAccessOnTheValidatedResources_IsRejectedEvenWithoutTheRawScope()
    {
        var context = ValidationContext();
        context.Request.ValidatedResources = new ResourceValidationResult(new Resources { OfflineAccess = true });

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result.IsError.Should().BeTrue();
        context.Result.Error.Should().Be(OidcConstants.TokenErrors.InvalidScope);
    }

    /// <summary>The unchanged happy path: without <c>offline_access</c> the grant still issues.</summary>
    [Fact]
    public async Task WithoutOfflineAccess_TheGrantSucceedsUnchanged()
    {
        var context = ValidationContext(scope: "openid octo_api");

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result.IsError.Should().BeFalse(context.Result.ErrorDescription);
        context.Result.Subject!.FindFirst(JwtClaimTypes.Subject)!.Value.Should().Be(UserSubjectId,
            "the delegated token runs on the USER's sub");
        context.Result.Subject.FindFirst(DelegationConstants.ActClaimType)!.Value
            .Should().Be(ServiceAccountClientId);
        context.Result.Subject.FindAll(DelegationConstants.DelegatedRoleClaimType)
            .Select(c => c.Value).Should().BeEquivalentTo("AssetReader");

        await _events.Received(1).RaiseAsync(Arg.Any<DelegationSuccessEvent>(), Arg.Any<CancellationToken>());
        await _events.DidNotReceive().RaiseAsync(Arg.Any<DelegationFailureEvent>(), Arg.Any<CancellationToken>());
    }

    /// <summary>A request with no <c>scope</c> parameter at all is the normal delegation shape.</summary>
    [Fact]
    public async Task NoScopeParameterAtAll_TheGrantSucceedsUnchanged()
    {
        var context = ValidationContext();

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result.IsError.Should().BeFalse(context.Result.ErrorDescription);
    }

    /// <summary>
    ///     The scope list is tokenised, not substring-matched — a scope that merely contains
    ///     "offline_access" as a prefix is a different scope and must not be swept up.
    /// </summary>
    [Fact]
    public async Task ScopeMerelyContainingOfflineAccessAsASubstring_IsNotRejected()
    {
        var context = ValidationContext(scope: "openid offline_access_report");

        await _sut.ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result.IsError.Should().BeFalse(context.Result.ErrorDescription);
    }

    // ---------- helpers ----------

    private ExtensionGrantValidationContext ValidationContext(string? scope = null, string? subjectToken = null)
    {
        var raw = new NameValueCollection
        {
            { OidcConstants.TokenRequest.SubjectToken, subjectToken ?? CreateSubjectToken() },
            {
                OidcConstants.TokenRequest.SubjectTokenType,
                "urn:ietf:params:oauth:token-type:access_token"
            },
            { OidcConstants.AuthorizeRequest.AcrValues, $"tenant:{TenantId}" }
        };

        if (scope != null)
        {
            raw.Add(OidcConstants.TokenRequest.Scope, scope);
        }

        var request = new ValidatedTokenRequest
        {
            GrantType = DelegationConstants.OnBehalfOfGrantType,
            Raw = raw
        };

        // SetClient — not a plain `Client = …` initializer — is what Duende's TokenRequestValidator
        // calls once the client credentials are verified, and it is the only path that populates
        // ValidatedRequest.ClientId (which the validator reads as the *proven* service-account id).
        request.SetClient(new Client { ClientId = ServiceAccountClientId });

        return new ExtensionGrantValidationContext { Request = request };
    }

    /// <summary>
    ///     A genuinely signed user access token: same issuer and signing key the validator resolves
    ///     from <see cref="IValidationKeysStore" />, carrying <c>sub</c> and <c>tenant_id</c>.
    /// </summary>
    private string CreateSubjectToken() =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority.EnsureEndsWith("/"),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object>
            {
                [JwtClaimTypes.Subject] = UserSubjectId,
                ["tenant_id"] = TenantId
            }
        });

    private static IReadOnlySet<string> RoleSet(params string[] roles) =>
        new HashSet<string>(roles, StringComparer.OrdinalIgnoreCase);
}
