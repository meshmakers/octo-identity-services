using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#5114 HTTP-level golden pin for the impersonation grant
///     (<c>urn:meshmakers:params:oauth:grant-type:impersonate</c>): an authenticated actor client
///     with a <c>System.Identity/MayActAs</c> edge to the target receives a token that is
///     byte-for-byte shaped like a <c>client_credentials</c> token OF THE TARGET —
///     <c>client_id</c> re-stamped to the target and <c>sub</c> stripped by
///     <c>OctoAccessTokenShapeHandler</c>, the TARGET's effective roles, <c>tenant_id</c>,
///     <c>act</c> naming the actor, <c>amr=impersonation</c>, and never a refresh token.
/// </summary>
/// <remarks>
///     <para>
///         The unit suite pins the processor policy over substituted stores and the persistence
///         suite pins the <c>MayActAs</c> edge semantics against real MongoDB
///         (<c>ImpersonatedIdentityIntegrationTests</c>); what only THIS test proves is the wire:
///         the full OpenIddict pipeline including <c>OctoAccessTokenShapeHandler</c>'s
///         client_id re-stamp + sub strip, which no in-process test exercises.
///     </para>
///     <para>
///         The delegated on-behalf-of variant with <c>requested_client_id</c> (actor delegates
///         through a service account it holds an edge to) has NO HTTP golden yet: it needs a user
///         subject token (authorization-code dance) plus user/SA role seeding on top of this
///         arrangement — pinned in-process by <c>OnBehalfOfProcessorTests</c> and
///         <c>DelegatedIdentityIntegrationTests</c> instead.
///     </para>
/// </remarks>
public class ImpersonationHttpGoldenTests : IntegrationTestBase
{
    private const string ImpersonationApiScope = "impersonation-api";
    private const string ImpersonationApiResource = "impersonation-api-resource";
    private const string ActorClientId = "impersonation-actor";
    private const string TargetClientId = "impersonation-target";
    private const string ActorSecret = "impersonation-actor-secret";

    public ImpersonationHttpGoldenTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    /// <summary>
    ///     The happy path over the real token endpoint, pinned as a golden: CC-shaped token for
    ///     the TARGET (client_id = target, target roles, tenant_id, NO sub), act = actor,
    ///     amr = impersonation, no refresh_token in the response.
    /// </summary>
    [Fact]
    public async Task Impersonation_AccessTokenShape_MatchesGoldenBaseline()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureImpersonationApiResourcesAsync();

        // Actor (the adapter's chart client): confidential, opted into the impersonation grant.
        var actor = await CreateImpersonationClientAsync(ActorClientId, builder => builder
            .WithGrantTypes(ImpersonationConstants.ImpersonationGrantType)
            .WithScopes(ImpersonationApiScope)
            .WithSecret("SharedSecret", Sha256Base64(ActorSecret))
            .RequireClientSecret()
            .RequirePkce(false));

        // Target (the pipeline service account): its secret is never used — that is the point.
        var target = await CreateImpersonationClientAsync(TargetClientId, builder => builder
            .WithGrantTypes("client_credentials")
            .WithScopes(ImpersonationApiScope)
            .RequirePkce(false));

        // Two direct roles pin the multi-value role claim shape (JSON array, like a genuine
        // client_credentials token of a multi-role client would carry).
        await AssignClientRoleAsync(target.RtId, "ImpersonationTargetRoleA");
        await AssignClientRoleAsync(target.RtId, "ImpersonationTargetRoleB");

        await WriteMayActAsEdgeAsync(actor.RtId, target.RtId);

        var response = await PostImpersonationTokenRequestAsync(ActorClientId, ActorSecret, TargetClientId, ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "impersonation token request failed: {0}", raw);
        var body = JsonNode.Parse(raw)!.AsObject();

        // Explicit invariants FIRST (they must hold even on a golden record run, which skips):
        body.ContainsKey("refresh_token").Should().BeFalse(
            "impersonated identities are never refreshable — the MayActAs authorization is evaluated at issuance only");

        var token = new JsonWebToken(body["access_token"]!.GetValue<string>());
        token.Claims.Should().NotContain(c => c.Type == "sub",
            "the platform recognizes a service token by the ABSENCE of sub — OctoAccessTokenShapeHandler must strip it");
        token.GetClaim("client_id").Value.Should().Be(TargetClientId,
            "the token is client-credentials-shaped FOR THE TARGET — OctoAccessTokenShapeHandler re-stamps client_id");
        token.GetClaim(ImpersonationConstants.ActClaimType).Value.Should().Be(ActorClientId,
            "act is the only trace of the caller on the issued token");
        token.GetClaim("amr").Value.Should().Be(ImpersonationConstants.AuthenticationMethod);

        await GoldenFile.MatchAllAsync(ct,
            ("impersonation-token-response",
                GoldenFile.NormalizeResponseShape(body, "token_type", "expires_in", "scope")),
            ("impersonation-access-token",
                GoldenFile.NormalizeJwt(body["access_token"]!.GetValue<string>())));
    }

    /// <summary>
    ///     No edge, no token — the whole authorization model at the wire: without the MayActAs
    ///     edge the SAME request yields the standard OAuth error response.
    /// </summary>
    [Fact]
    public async Task Impersonation_WithoutMayActAsEdge_IsRejectedWithInvalidGrant()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureImpersonationApiResourcesAsync();

        const string lonelyActorId = "impersonation-actor-noedge";
        const string lonelyTargetId = "impersonation-target-noedge";
        await CreateImpersonationClientAsync(lonelyActorId, builder => builder
            .WithGrantTypes(ImpersonationConstants.ImpersonationGrantType)
            .WithScopes(ImpersonationApiScope)
            .WithSecret("SharedSecret", Sha256Base64(ActorSecret))
            .RequireClientSecret()
            .RequirePkce(false));
        await CreateImpersonationClientAsync(lonelyTargetId, builder => builder
            .WithGrantTypes("client_credentials")
            .WithScopes(ImpersonationApiScope)
            .RequirePkce(false));
        // Deliberately NO MayActAs edge.

        var response = await PostImpersonationTokenRequestAsync(lonelyActorId, ActorSecret, lonelyTargetId, ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "an unauthorized impersonation attempt must be an OAuth protocol error, got: {0}", raw);
        var body = JsonNode.Parse(raw)!.AsObject();
        body["error"]!.GetValue<string>().Should().Be("invalid_grant");
        body["error_description"]!.GetValue<string>().Should()
            .Be("the authenticated client is not authorized to act as the requested client",
                "the denial must come from the MayActAs check, not from grant/permission plumbing: {0}", raw);
    }

    #region Arrange helpers

    private Task<HttpResponseMessage> PostImpersonationTokenRequestAsync(
        string actorClientId, string actorSecret, string targetClientId, CancellationToken ct)
    {
        var client = CreateAnonymousClient();
        return client.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = ImpersonationConstants.ImpersonationGrantType,
                ["client_id"] = actorClientId,
                ["client_secret"] = actorSecret,
                [ImpersonationConstants.RequestedClientIdParameter] = targetClientId,
                ["scope"] = ImpersonationApiScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
    }

    /// <summary>
    ///     Creates the impersonation API scope and an API resource carrying it, so issued access
    ///     tokens get the <c>aud</c> claim the resource services validate. Idempotent per factory.
    /// </summary>
    private async Task EnsureImpersonationApiResourcesAsync()
    {
        using var scope = CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();

        if (await resourceStore.GetApiScopeByNameAsync(ImpersonationApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ImpersonationApiScope,
                DisplayName = "Impersonation API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }

        if (await resourceStore.GetApiResourceByNameAsync(ImpersonationApiResource) == null)
        {
            await resourceStore.CreateApiResourceAsync(new RtApiResource
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ImpersonationApiResource,
                DisplayName = "Impersonation API Resource",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                Scopes = new AttributeStringValueList { ImpersonationApiScope }
            });
        }
    }

    private async Task<RtClient> CreateImpersonationClientAsync(string clientId, Action<RtClientBuilder> configure)
    {
        using var scope = CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();

        var existing = await clientStore.FindRtClientByIdAsync(clientId);
        if (existing != null)
        {
            return existing;
        }

        var builder = new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId);
        configure(builder);
        var client = builder.Build();
        await clientStore.CreateAsync(client);
        return client;
    }

    /// <summary>
    ///     Assigns an effective role to a client the same way the client-credentials golden does —
    ///     the impersonated token must resolve the target's roles through the same
    ///     <c>ClientRoleStore</c> path.
    /// </summary>
    private async Task AssignClientRoleAsync(OctoObjectId clientRtId, string roleName)
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();

        if (await roleManager.FindByNameAsync(roleName) == null)
        {
            var result = await roleManager.CreateAsync(new RtRoleBuilder().WithName(roleName).Build());
            result.Succeeded.Should().BeTrue("role creation failed: {0}",
                string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        var clientRoleStore = scope.ServiceProvider.GetRequiredService<IClientRoleStore>();
        await clientRoleStore.AddRoleAsync(clientRtId, roleName);
    }

    /// <summary>
    ///     Writes the <c>System.Identity/MayActAs</c> edge actor→target exactly the way the
    ///     identity-data consumer materialises it, through the factory's own tenant repository.
    /// </summary>
    private async Task WriteMayActAsEdgeAsync(OctoObjectId actorRtId, OctoObjectId targetRtId)
    {
        using var scope = CreateScope();
        var multiTenancyResolver = scope.ServiceProvider.GetRequiredService<IMultiTenancyResolverService>();
        var repo = multiTenancyResolver.GetTenantRepository();

        var clientCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtClient>();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var updates = new List<AssociationUpdateInfo>
        {
            AssociationUpdateInfo.CreateInsert(
                new RtEntityId(clientCkTypeId, actorRtId),
                new RtEntityId(clientCkTypeId, targetRtId),
                IdentityAssociationConstants.MayActAsId)
        };
        var operationResult = new OperationResult();
        await repo.ApplyChangesAsync(session, updates, operationResult);
        await session.CommitTransactionAsync();
        operationResult.HasErrors.Should().BeFalse(string.Join("; ", operationResult.GetMessages()));
    }

    private static string Sha256Base64(string value)
        => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    #endregion
}
