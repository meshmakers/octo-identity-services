using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

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

    private readonly IClientMirrorProvisioningService _mirrorService =
        Substitute.For<IClientMirrorProvisioningService>();

    private readonly IIdentityAuditService _auditService = Substitute.For<IIdentityAuditService>();
    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly HttpContextAccessor _httpContextAccessor = new();

    public ClientCredentialsTenantAmbiguityTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);
        _mirrorService.GetMirrorsAsync(Arg.Any<string>(), Arg.Any<string>())
            .Returns((IReadOnlyList<RtClientMirror>)Array.Empty<RtClientMirror>());
    }

    private ClientCredentialsTenantProcessor CreateProcessor() => new(
        _mirrorService, _httpContextAccessor, _systemContext, _auditService,
        NullLogger<ClientCredentialsTenantProcessor>.Instance);

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

    private static RtClientMirror Mirror(string childTenantId) => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        ParentClientId = ClientId,
        ParentTenantId = SystemTenantId,
        ChildTenantId = childTenantId,
        ProvisionedAt = DateTime.UtcNow,
        SecretHashVersion = 0
    };

    private static void AssertRefused(ClientCredentialsTenantProcessor.TenantBindingOutcome outcome)
    {
        outcome.Error.Should().Be(Errors.InvalidRequest);
        outcome.ErrorDescription.Should()
            .Be(ClientCredentialsTenantProcessor.AmbiguousTenantErrorDescription);

        // The whole point: no tenant may be guessed onto a refused request. The controller aborts on
        // Error, so a TenantId here would be a claim on a token that must never be issued.
        outcome.TenantId.Should().BeNull();
    }

    [Fact]
    public async Task MirroringSourceClient_WithoutAcrValues_IsRefusedInsteadOfStampedWithSystem()
    {
        // The exact hole: same client id + same secret live in every child tenant, so "found in the
        // system tenant" says nothing about where the caller belongs.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .WithAutoProvisionInChildTenants()
            .Build();
        ResolveRequestToTenant(null);

        var outcome = await CreateProcessor().ResolveAsync(ClientId, client);

        AssertRefused(outcome);
        await _auditService.Received(1).StoreFailureAsync(
            ClientCredentialsTenantProcessor.AmbiguityAuditEventName,
            Arg.Is<string>(m => m.Contains(ClientId, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ClientWithLiveMirrors_WithoutAcrValues_IsRefusedEvenWhenTheFlagWasSwitchedOff()
    {
        // Turning the flag off stops *further* mirroring; it does not retract the mirrors already
        // made — so the client id stays ambiguous and the tracking rows are the only witness.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .WithAutoProvisionInChildTenants(false)
            .Build();
        _mirrorService.GetMirrorsAsync(SystemTenantId, ClientId)
            .Returns((IReadOnlyList<RtClientMirror>) [Mirror(ChildTenantId)]);
        ResolveRequestToTenant(null);

        AssertRefused(await CreateProcessor().ResolveAsync(ClientId, client));
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
        ResolveRequestToTenant(null);

        AssertRefused(await CreateProcessor().ResolveAsync(ClientId, mirrorCopy));
    }

    [Fact]
    public async Task MirrorLookupFailure_WithoutAcrValues_FailsClosed()
    {
        // Guessing "system tenant" on a failed lookup would reopen exactly the hole being closed.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build();
        _mirrorService.GetMirrorsAsync(SystemTenantId, ClientId)
            .Returns<IReadOnlyList<RtClientMirror>>(_ => throw new InvalidOperationException("repo down"));
        ResolveRequestToTenant(null);

        AssertRefused(await CreateProcessor().ResolveAsync(ClientId, client));
    }

    [Fact]
    public async Task UnambiguousClient_WithoutAcrValues_StillCarriesTheSystemTenant()
    {
        // Backwards compatibility for every caller found in the AB#5058 caller inventory that omits
        // acr_values today (octo-sdk sample, the documented curl recipe): unchanged behaviour.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build();
        ResolveRequestToTenant(null);

        var outcome = await CreateProcessor().ResolveAsync(ClientId, client);

        outcome.Error.Should().BeNull();
        outcome.TenantId.Should().Be(SystemTenantId);
    }

    [Fact]
    public async Task MirroringSourceClient_WithAcrValues_IsUnchanged()
    {
        // A caller that names its tenant is unambiguous by construction — the mirroring feature keeps
        // working exactly as before, and the ambiguity probe is not even consulted.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .WithAutoProvisionInChildTenants()
            .Build();
        ResolveRequestToTenant(ChildTenantId);

        var outcome = await CreateProcessor().ResolveAsync(ClientId, client);

        outcome.Error.Should().BeNull();
        outcome.TenantId.Should().Be(ChildTenantId);
        await _mirrorService.DidNotReceive().GetMirrorsAsync(Arg.Any<string>(), Arg.Any<string>());
    }

    /// <summary>
    ///     A refused request must not be audited as a success, and an accepted one must not be
    ///     audited at all — the persisted entry is the operator's only durable trace of a caller
    ///     still relying on the removed fall-back, so a false entry would send them hunting.
    /// </summary>
    [Fact]
    public async Task AcceptedRequest_IsNotAudited()
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build();
        ResolveRequestToTenant(ChildTenantId);

        await CreateProcessor().ResolveAsync(ClientId, client);

        await _auditService.DidNotReceive().StoreFailureAsync(Arg.Any<string>(), Arg.Any<string>());
    }
}
