using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using IdentityServices.IntegrationTests.Helpers;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     End-to-end checks of the impersonation authorization (AB#5114) against a real MongoDB
///     (Testcontainers) with the full Octo runtime engine.
/// </summary>
/// <remarks>
///     <para>
///         The unit suite pins the policy over substituted stores; what can only be proven here is
///         the CK-association layer: the <c>System.Identity/MayActAs</c> edge introduced with
///         System.Identity 2.14.0 really is writable and queryable between two <c>Client</c>
///         entities, the edge check is direction-sensitive, and the granted role set resolves the
///         way the client-credentials token pipeline does (direct <c>AssignedRole</c> edges plus
///         group-inherited roles, via <see cref="ClientRoleStore" />).
///     </para>
///     <para>
///         Clients, roles and groups are created in-test so the assertions do not depend on what
///         the blueprint seed provisions in the fixture.
///     </para>
/// </remarks>
[Collection("Sequential")]
public class ImpersonatedIdentityIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ImpersonatedIdentityIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    /// <summary>
    ///     THE impersonation invariant over real graphs: with the edge in place the actor receives
    ///     exactly the TARGET's effective roles — direct and group-inherited — and none of its own.
    /// </summary>
    [Fact]
    public async Task Impersonation_WithMayActAsEdge_ResolvesTheTargetsRoles_NotTheActors()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, groupStore, repo) = CreateFixtureStores();

        var targetDirect = NewId("tDirect");
        var targetViaGroup = NewId("tGroup");
        var actorOnly = NewId("aOnly");

        await CreateRoleAsync(repo, targetDirect);
        var targetViaGroupId = await CreateRoleAsync(repo, targetViaGroup);
        var actorOnlyId = await CreateRoleAsync(repo, actorOnly);

        // Target SA: one direct role + one inherited through group membership.
        var targetClientId = NewId("sa");
        var targetRtId = await CreateClientAsync(repo, targetClientId);
        var clientRoleStore = CreateClientRoleStore(repo);
        await clientRoleStore.AddRoleAsync(targetRtId, targetDirect);
        var group = await CreateGroupAsync(repo, NewId("gSa"));
        await groupStore.SetRoleIdsAsync(group, [targetViaGroupId.ToString()]);
        await groupStore.AddMemberClientAsync(group, targetRtId.ToString());

        // Actor (the adapter's client): its own role must never surface on the impersonated token.
        var actorClientId = NewId("adp");
        var actorRtId = await CreateClientAsync(repo, actorClientId);
        await AssignRoleDirectlyAsync(repo, actorRtId, actorOnlyId);

        await WriteMayActAsEdgeAsync(repo, actorRtId, targetRtId);

        var result = await resolver.ResolveAsync(actorClientId, targetClientId,
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeTrue();
        result.EffectiveRoleNames.Should().BeEquivalentTo([targetDirect, targetViaGroup],
            "the impersonated identity carries the TARGET's direct plus group-inherited roles");
        result.EffectiveRoleNames.Should().NotContain(actorOnly,
            "nothing of the actor's own authority may travel into the impersonated token");
    }

    /// <summary>No edge, no grant — the whole authorization model in one test.</summary>
    [Fact]
    public async Task Impersonation_WithoutEdge_IsDeniedAsNotAuthorized()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var actorClientId = NewId("adpN");
        var targetClientId = NewId("saN");
        await CreateClientAsync(repo, actorClientId);
        await CreateClientAsync(repo, targetClientId);

        var result = await resolver.ResolveAsync(actorClientId, targetClientId,
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.NotAuthorized);
    }

    /// <summary>
    ///     The edge is directional: target→actor must not authorize actor→target — otherwise every
    ///     pipeline SA could become its adapter.
    /// </summary>
    [Fact]
    public async Task Impersonation_ReversedEdge_DoesNotAuthorize()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var actorClientId = NewId("adpR");
        var targetClientId = NewId("saR");
        var actorRtId = await CreateClientAsync(repo, actorClientId);
        var targetRtId = await CreateClientAsync(repo, targetClientId);

        // Deliberately the wrong direction.
        await WriteMayActAsEdgeAsync(repo, targetRtId, actorRtId);

        var result = await resolver.ResolveAsync(actorClientId, targetClientId,
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.NotAuthorized);
    }

    /// <summary>Disabling the target kills impersonation too — no side door around the switch.</summary>
    [Fact]
    public async Task Impersonation_DisabledTarget_IsDenied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var actorClientId = NewId("adpD");
        var targetClientId = NewId("saD");
        var actorRtId = await CreateClientAsync(repo, actorClientId);
        var targetRtId = await CreateClientAsync(repo, targetClientId, enabled: false);
        await WriteMayActAsEdgeAsync(repo, actorRtId, targetRtId);

        var result = await resolver.ResolveAsync(actorClientId, targetClientId,
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.TargetDisabled);
    }

    [Fact]
    public async Task Impersonation_UnknownTarget_IsDenied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var actorClientId = NewId("adpU");
        await CreateClientAsync(repo, actorClientId);

        var result = await resolver.ResolveAsync(actorClientId, NewId("ghost"),
            TestContext.Current.CancellationToken);

        result.IsGranted.Should().BeFalse();
        result.DenialReason.Should().Be(ImpersonationDenialReason.TargetNotFound);
    }

    /// <summary>
    ///     The gate-only entry point the on-behalf-of extension (AB#5114) uses: authorized with the
    ///     edge, denied without — against the real association store.
    /// </summary>
    [Fact]
    public async Task AuthorizeActor_MirrorsTheEdge()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _, repo) = CreateFixtureStores();

        var actorClientId = NewId("adpA");
        var targetClientId = NewId("saA");
        var actorRtId = await CreateClientAsync(repo, actorClientId);
        var targetRtId = await CreateClientAsync(repo, targetClientId);

        (await resolver.AuthorizeActorAsync(actorClientId, targetClientId,
                TestContext.Current.CancellationToken))
            .Should().Be(ImpersonationDenialReason.NotAuthorized);

        await WriteMayActAsEdgeAsync(repo, actorRtId, targetRtId);

        (await resolver.AuthorizeActorAsync(actorClientId, targetClientId,
                TestContext.Current.CancellationToken))
            .Should().Be(ImpersonationDenialReason.None);
    }

    // ---------- MayActAs read surface (GET Clients/{id}/actors, AB#5114) ----------

    /// <summary>
    ///     The store read behind <c>GET {tenantId}/v1/Clients/{id}/actors</c>: an inbound edge
    ///     lists the actor's CLIENT id, and the read is direction-sensitive — the actor's own
    ///     actor list stays empty, an outbound-only relationship never reports the target as the
    ///     actor's actor.
    /// </summary>
    [Fact]
    public async Task ActorRead_EdgePresent_ListsTheActorInboundOnly()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (_, _, repo) = CreateFixtureStores();
        var store = new ClientImpersonationStore(new FixedTenantResolver(repo));

        var actorClientId = NewId("adpL");
        var targetClientId = NewId("saL");
        var actorRtId = await CreateClientAsync(repo, actorClientId);
        var targetRtId = await CreateClientAsync(repo, targetClientId);

        await WriteMayActAsEdgeAsync(repo, actorRtId, targetRtId);

        (await store.GetActorClientIdsAsync(targetRtId))
            .Should().BeEquivalentTo([actorClientId],
                "the target's actor list is exactly the origins of its inbound MayActAs edges");
        (await store.GetActorClientIdsAsync(actorRtId))
            .Should().BeEmpty(
                "the edge is directional — being an actor FOR someone must not surface as having an actor");
    }

    [Fact]
    public async Task ActorRead_NoEdges_ReturnsEmpty()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (_, _, repo) = CreateFixtureStores();
        var store = new ClientImpersonationStore(new FixedTenantResolver(repo));

        var lonelyRtId = await CreateClientAsync(repo, NewId("saE"));

        (await store.GetActorClientIdsAsync(lonelyRtId)).Should().BeEmpty();
    }

    [Fact]
    public async Task ActorRead_UnknownClient_ReturnsEmpty()
    {
        // Store level: unknown rtId answers empty; the REST endpoint 404s from the client lookup
        // before ever consulting the store.
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (_, _, repo) = CreateFixtureStores();
        var store = new ClientImpersonationStore(new FixedTenantResolver(repo));

        (await store.GetActorClientIdsAsync(OctoObjectId.GenerateNewId())).Should().BeEmpty();
    }

    // ---------- helpers ----------

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    /// <summary>
    ///     Wires the real resolver to the system tenant repository, exactly as the DI graph does per
    ///     request — client store, client role store and the MayActAs edge store all read through
    ///     the same tenant repository.
    /// </summary>
    private (ImpersonatedIdentityResolver resolver, GroupStore groupStore, ITenantRepository repo)
        CreateFixtureStores()
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        var tenantResolver = new FixedTenantResolver(repo);
        var groupStore = new GroupStore(tenantResolver);

        var resolver = new ImpersonatedIdentityResolver(
            new ClientStore(tenantResolver),
            CreateClientRoleStore(repo),
            new ClientImpersonationStore(tenantResolver),
            NullLogger<ImpersonatedIdentityResolver>.Instance);

        return (resolver, groupStore, repo);
    }

    private static ClientRoleStore CreateClientRoleStore(ITenantRepository repo)
    {
        var tenantResolver = new FixedTenantResolver(repo);
        return new ClientRoleStore(
            tenantResolver,
            new GroupRoleResolver(new GroupStore(tenantResolver)),
            NullLogger<ClientRoleStore>.Instance);
    }

    private static async Task<OctoObjectId> CreateRoleAsync(ITenantRepository repo, string name)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = rtId,
            Name = name,
            NormalizedName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> CreateClientAsync(ITenantRepository repo, string clientId,
        bool enabled = true)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = enabled,
            ClientId = clientId,
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList
            {
                "client_credentials",
                "urn:meshmakers:params:oauth:grant-type:impersonate"
            },
            AllowedScopes = new AttributeStringValueList { "octo_api" }
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> CreateGroupAsync(ITenantRepository repo, string name)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtGroup
        {
            RtId = rtId,
            GroupName = name,
            NormalizedGroupName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task AssignRoleDirectlyAsync(ITenantRepository repo, OctoObjectId clientRtId,
        OctoObjectId roleRtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var updates = new List<AssociationUpdateInfo>
        {
            AssociationUpdateInfo.CreateInsert(
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), clientRtId),
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), roleRtId),
                IdentityAssociationConstants.AssignedRoleId)
        };
        var operationResult = new OperationResult();
        await repo.ApplyChangesAsync(session, updates, operationResult);
        await session.CommitTransactionAsync();
        operationResult.HasErrors.Should().BeFalse();
    }

    /// <summary>Writes the MayActAs edge exactly the way the identity-data consumer materialises it.</summary>
    private static async Task WriteMayActAsEdgeAsync(ITenantRepository repo, OctoObjectId actorRtId,
        OctoObjectId targetRtId)
    {
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
}
