using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityModel;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5058 — pins that a <c>client_credentials</c> request without <c>acr_values</c> is
///     <b>refused</b> whenever the presented client id is not unambiguously bound to a single
///     tenant, instead of being silently stamped with the system tenant.
/// </summary>
/// <remarks>
///     AB#5032 reasoned that "the client store resolved this client against the system tenant, so
///     the token belongs there". Client mirroring breaks that reasoning: a client flagged
///     <c>AutoProvisionInChildTenants</c> is provisioned into every child tenant with the <b>same</b>
///     client id and the <b>same</b> secret, so a caller holding a child tenant's credentials could
///     simply omit <c>acr_values</c> and receive a system-tenant token — making every "is the caller
///     in the system tenant" check (AB#5055) trivially satisfiable with a service token.
///     The decision is made server-side, from state the caller cannot influence.
/// </remarks>
public class ClientCredentialsTenantAmbiguityTests
{
    private const string ClientId = "octo-cicd-agent";
    private const string ChildTenantId = "meshtest";
    private const string SystemTenantId = "octosystem";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();

    private readonly IClientMirrorProvisioningService _mirrorService =
        Substitute.For<IClientMirrorProvisioningService>();

    private readonly IEventService _events = Substitute.For<IEventService>();
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly HttpContextAccessor _httpContextAccessor = new();

    public ClientCredentialsTenantAmbiguityTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);
        _mirrorService.GetMirrorsAsync(Arg.Any<string>(), Arg.Any<string>())
            .Returns((IReadOnlyList<RtClientMirror>)Array.Empty<RtClientMirror>());
        _clientRoleStore.GetEffectiveRoleNamesAsync(Arg.Any<OctoObjectId>())
            .Returns((IReadOnlySet<string>)new HashSet<string>());
    }

    private ClientCredentialsRoleTokenValidator CreateValidator() => new(
        _clientStore, _clientRoleStore, _mirrorService, _events, _httpContextAccessor, _systemContext,
        NullLogger<ClientCredentialsRoleTokenValidator>.Instance);

    private static CustomTokenRequestValidationContext CreateContext()
    {
        var request = new ValidatedTokenRequest { GrantType = GrantType.ClientCredentials };
        request.SetClient(new Client { ClientId = ClientId });
        return new CustomTokenRequestValidationContext { Result = new TokenRequestValidationResult(request) };
    }

    /// <summary>Simulates what <c>OidcTenantResolutionMiddleware</c> writes for this request.</summary>
    private void ResolveRequestToTenant(string? tenantId)
    {
        var httpContext = new DefaultHttpContext();
        if (tenantId != null)
        {
            httpContext.Items[InfrastructureCommon.TenantIdName] = tenantId;
        }

        _httpContextAccessor.HttpContext = httpContext;
    }

    private void RegisterClient(RtClient client)
        => _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);

    private static RtClientMirror Mirror(string childTenantId) => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        ParentClientId = ClientId,
        ParentTenantId = SystemTenantId,
        ChildTenantId = childTenantId,
        ProvisionedAt = DateTime.UtcNow,
        SecretHashVersion = 0
    };

    private static void AssertRejected(CustomTokenRequestValidationContext context)
    {
        context.Result!.IsError.Should().BeTrue();
        context.Result.Error.Should().Be(OidcConstants.TokenErrors.InvalidRequest);
        context.Result.ErrorDescription.Should()
            .Be(ClientCredentialsRoleTokenValidator.AmbiguousTenantErrorDescription);

        // The whole point: no tenant may be guessed onto a refused request.
        context.Result.ValidatedRequest.ClientClaims.Should()
            .NotContain(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType);
    }

    [Fact]
    public async Task MirroringSourceClient_WithoutAcrValues_IsRefusedInsteadOfStampedWithSystem()
    {
        // The exact hole: same client id + same secret live in every child tenant, so "found in the
        // system tenant" says nothing about where the caller belongs.
        RegisterClient(new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .WithAutoProvisionInChildTenants()
            .Build());
        ResolveRequestToTenant(null);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertRejected(context);
        await _events.Received(1).RaiseAsync(
            Arg.Any<ClientCredentialsTenantAmbiguityEvent>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ClientWithLiveMirrors_WithoutAcrValues_IsRefusedEvenWhenTheFlagWasSwitchedOff()
    {
        // Turning the flag off stops *further* mirroring; it does not retract the mirrors already
        // made — so the client id stays ambiguous and the tracking rows are the only witness.
        RegisterClient(new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .WithAutoProvisionInChildTenants(false)
            .Build());
        _mirrorService.GetMirrorsAsync(SystemTenantId, ClientId)
            .Returns((IReadOnlyList<RtClientMirror>) [Mirror(ChildTenantId)]);
        ResolveRequestToTenant(null);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertRejected(context);
    }

    [Fact]
    public async Task MirrorCopyItself_WithoutAcrValues_IsRefused()
    {
        // Defensive: reachable when the resolved directory is itself a child tenant. The marker is
        // written by ClientMirrorProvisioningService and cannot be set by the caller.
        var mirrorCopy = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build();
        mirrorCopy.ProvisionedByParentTenantId = SystemTenantId;
        RegisterClient(mirrorCopy);
        ResolveRequestToTenant(null);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertRejected(context);
    }

    [Fact]
    public async Task MirrorLookupFailure_WithoutAcrValues_FailsClosed()
    {
        // Guessing "system tenant" on a failed lookup would reopen exactly the hole being closed.
        RegisterClient(new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build());
        _mirrorService.GetMirrorsAsync(SystemTenantId, ClientId)
            .Returns<IReadOnlyList<RtClientMirror>>(_ => throw new InvalidOperationException("repo down"));
        ResolveRequestToTenant(null);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        AssertRejected(context);
    }

    [Fact]
    public async Task AmbiguousClient_WithoutAcrValues_NeverReachesTheRoleBranch()
    {
        RegisterClient(new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .WithAutoProvisionInChildTenants()
            .Build());
        ResolveRequestToTenant(null);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        await _clientRoleStore.DidNotReceive().GetEffectiveRoleNamesAsync(Arg.Any<OctoObjectId>());
        context.Result!.ValidatedRequest.ClientClaims.Should().BeEmpty();
    }

    [Fact]
    public async Task UnambiguousClient_WithoutAcrValues_StillCarriesTheSystemTenant()
    {
        // Backwards compatibility for every caller found in the AB#5058 caller inventory that omits
        // acr_values today (octo-sdk sample, the documented curl recipe): unchanged behaviour.
        RegisterClient(new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build());
        ResolveRequestToTenant(null);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.IsError.Should().BeFalse();
        context.Result.ValidatedRequest.ClientClaims.Should()
            .ContainSingle(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType)
            .Which.Value.Should().Be(SystemTenantId);
    }

    [Fact]
    public async Task MirroringSourceClient_WithAcrValues_IsUnchanged()
    {
        // A caller that names its tenant is unambiguous by construction — the mirroring feature keeps
        // working exactly as before, and the ambiguity probe is not even consulted.
        RegisterClient(new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .WithAutoProvisionInChildTenants()
            .Build());
        ResolveRequestToTenant(ChildTenantId);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.IsError.Should().BeFalse();
        context.Result.ValidatedRequest.ClientClaims.Should()
            .ContainSingle(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType)
            .Which.Value.Should().Be(ChildTenantId);
        await _mirrorService.DidNotReceive().GetMirrorsAsync(Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task AB5032Semantics_TenantClaimIsStampedBeforeTheRoleBranchBailsOut()
    {
        // The AB#5032 invariant this change must not regress: a role-less client still gets tenant_id.
        RegisterClient(new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build());
        ResolveRequestToTenant(ChildTenantId);
        var context = CreateContext();

        await CreateValidator().ValidateAsync(context, TestContext.Current.CancellationToken);

        context.Result!.ValidatedRequest.ClientClaims.Should()
            .ContainSingle(c => c.Type == ClientCredentialsRoleTokenValidator.TenantIdClaimType);
        context.Result.ValidatedRequest.Client.ClientClaimsPrefix.Should().BeNull();
    }
}
