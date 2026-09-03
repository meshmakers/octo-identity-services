using FluentAssertions;
using IdentityServerPersistence;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands.Payloads;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// AB#5027 phase 2, identity side: the distribution-event-hub path is the only channel the
/// Communication Controller has to this service (the REST client-create API needs an
/// <c>octo_api</c> bearer token — i.e. the very service account it is trying to create), so the
/// pipeline service account has to be creatable over the bus, <b>with</b> a secret and <b>with</b>
/// roles. Both were impossible before: the consumer hard-coded <c>RequireClientSecret=false</c>,
/// never wrote a <c>ClientSecrets</c> entry, and never touched an association.
///
/// <para>
/// Run against a real MongoDB (Testcontainers) so the CK writes, the record-array secret and the
/// <c>AssignedRole</c> edge are exercised for real.
/// </para>
/// </summary>
[Collection("Sequential")]
public class ServiceAccountClientProvisioningIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ServiceAccountClientProvisioningIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ServiceAccountClient_IsCreatedWithHashedSecretGrantsScopeAndRole()
    {
        await ArrangeAsync();
        var clientId = NewClientId();
        const string secret = "plaintext-secret-one";

        await ConsumeAsync(BuildServiceAccountRequest(clientId, secret));

        var client = await LoadClientAsync(clientId);
        client.Should().NotBeNull();

        using var _ = new FluentAssertions.Execution.AssertionScope();
        client!.RequireClientSecret.Should().BeTrue("a client_credentials client without a secret hands a token to anyone who knows its id");
        // Only the hash is stored — the plaintext lives exclusively in the tenant-side
        // ServiceAccountConfiguration the adapter reads.
        client.ClientSecrets.Should().ContainSingle();
        client.ClientSecrets.Single().Value.Should().Be(OctoSecretHasher.HashSecret(secret));
        client.ClientSecrets.Single().Value.Should().NotBe(secret);
        client.AllowedGrantTypes.Should().Contain("client_credentials");
        // Precondition for AB#5031 — Duende gates its extension-grant validators on this list.
        client.AllowedGrantTypes.Should().Contain("urn:meshmakers:params:oauth:grant-type:on-behalf-of");
        client.AllowedScopes.Should().Contain(CommonConstants.OctoApiFullAccess);
        client.AllowOfflineAccess.Should().BeFalse();

        (await GetAssignedRoleNamesAsync(client)).Should().Contain(CommonConstants.CommunicationManagementRole);
    }

    [Fact]
    public async Task SecondRunWithTheSameSecret_DoesNotRotateAndCreatesNoDuplicates()
    {
        await ArrangeAsync();
        var clientId = NewClientId();
        const string secret = "plaintext-secret-two";

        await ConsumeAsync(BuildServiceAccountRequest(clientId, secret));
        var afterFirst = await LoadClientAsync(clientId);

        await ConsumeAsync(BuildServiceAccountRequest(clientId, secret));

        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var clients = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));

        using var _ = new FluentAssertions.Execution.AssertionScope();
        clients.Items.Should().ContainSingle("the consumer keys on ClientId and must upsert, not duplicate");
        var afterSecond = clients.Items.Single();
        afterSecond.RtId.Should().Be(afterFirst!.RtId);
        // Same plaintext hashes to the same value, so nothing rotated — the adapter's cached
        // credential keeps working across every service restart.
        afterSecond.ClientSecrets.Single().Value.Should().Be(afterFirst.ClientSecrets.Single().Value);
        // The role edge is additive and idempotent — no second edge to the same role.
        (await GetAssignedRoleNamesAsync(afterSecond)).Should()
            .ContainSingle(n => n == CommonConstants.CommunicationManagementRole);
    }

    [Fact]
    public async Task RerunWithoutASecret_PreservesTheExistingOne()
    {
        await ArrangeAsync();
        var clientId = NewClientId();
        const string secret = "plaintext-secret-three";

        await ConsumeAsync(BuildServiceAccountRequest(clientId, secret));

        // A producer that predates AB#5027 (or one that deliberately does not re-issue) sends no
        // secret. The wholesale ReplaceOneRtEntityByIdAsync in the consumer would drop the live
        // secret without the preserve branch — harmless while no bus client had one, fatal now.
        await ConsumeAsync(BuildServiceAccountRequest(clientId, clientSecret: null));

        var client = await LoadClientAsync(clientId);
        client!.ClientSecrets.Should().ContainSingle();
        client.ClientSecrets.Single().Value.Should().Be(OctoSecretHasher.HashSecret(secret));
    }

    [Fact]
    public async Task ClientWithoutTheNewFields_StaysAPublicSecretlessClient()
    {
        await ArrangeAsync();
        var clientId = NewClientId();

        // Exactly the shape every pre-AB#5027 producer sends (swagger / SPA clients).
        await ConsumeAsync(new CreateIdentityDataCommandRequest(SystemTenantId)
        {
            Clients =
            [
                new DistClientDto(clientId, "legacy client", "https://example.com")
                {
                    AllowedGrantTypes = ["authorization_code"],
                    RedirectUris = [],
                    PostLogoutRedirectUris = [],
                    AllowedCorsOrigins = [],
                    AllowedScopes = [CommonConstants.OctoApiFullAccess]
                }
            ]
        });

        var client = await LoadClientAsync(clientId);

        using var _ = new FluentAssertions.Execution.AssertionScope();
        client!.RequireClientSecret.Should().BeFalse("the default must reproduce the pre-AB#5027 behaviour exactly");
        client.ClientSecrets.Should().BeEmpty();
        (await GetAssignedRoleNamesAsync(client)).Should().BeEmpty();
    }

    [Fact]
    public async Task UnknownRoleName_IsSkippedInsteadOfFailingTheWholeIdentityDataSetup()
    {
        await ArrangeAsync();
        var clientId = NewClientId();
        var request = BuildServiceAccountRequest(clientId, "plaintext-secret-four");
        request.Clients = [request.Clients!.Single() with { AssignedRoleNames = ["NoSuchRoleHere"] }];

        // The tenant's role seed runs on an independent trigger and may legitimately not have
        // landed yet (the SuccessIdentityDataSeedPending case). Losing the whole identity-data
        // setup over it would be far worse than a client that gets its roles on the next pass.
        await ConsumeAsync(request);

        var client = await LoadClientAsync(clientId);
        client.Should().NotBeNull();
        (await GetAssignedRoleNamesAsync(client!)).Should().BeEmpty();
    }

    // ---------- AB#5111: declarative role sync for pipeline service accounts ----------

    [Fact]
    public async Task DeclaredServiceAccount_SuperfluousRoleEdges_AreRemoved()
    {
        await ArrangeAsync();
        await EnsureRoleAsync("Ab5111ExtraRole");
        var clientId = NewClientId();
        var request = BuildServiceAccountRequest(clientId, "plaintext-secret-five");
        request.Clients =
        [
            request.Clients!.Single() with
            {
                AssignedRoleNames = [CommonConstants.CommunicationManagementRole, "Ab5111ExtraRole"]
            }
        ];
        await ConsumeAsync(request);

        // The declaration shrank — the octo-pipeline-sa- prefix opts the client into full sync
        // (AB#5111), so the edge outside the declared list must go, not linger.
        var shrunk = BuildServiceAccountRequest(clientId, "plaintext-secret-five");
        await ConsumeAsync(shrunk);

        var client = await LoadClientAsync(clientId);
        (await GetAssignedRoleNamesAsync(client!)).Should()
            .BeEquivalentTo([CommonConstants.CommunicationManagementRole]);
    }

    [Fact]
    public async Task DeclaredServiceAccount_EmptyDeclaration_RemovesEveryRoleEdge()
    {
        await ArrangeAsync();
        var clientId = NewClientId();
        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-six"));

        var request = BuildServiceAccountRequest(clientId, "plaintext-secret-six");
        request.Clients = [request.Clients!.Single() with { AssignedRoleNames = [] }];
        await ConsumeAsync(request);

        var client = await LoadClientAsync(clientId);
        (await GetAssignedRoleNamesAsync(client!)).Should().BeEmpty();
    }

    [Fact]
    public async Task DeclaredServiceAccount_NullRoleList_LeavesTheEdgesCompletelyAlone()
    {
        // The controller sends null for legacy (undeclared) accounts and for rotations — the
        // upgrade-safety half of AB#5111: role edges granted by hand or by a blueprint survive.
        await ArrangeAsync();
        var clientId = NewClientId();
        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-seven"));

        var request = BuildServiceAccountRequest(clientId, "plaintext-secret-seven");
        request.Clients = [request.Clients!.Single() with { AssignedRoleNames = null }];
        await ConsumeAsync(request);

        var client = await LoadClientAsync(clientId);
        (await GetAssignedRoleNamesAsync(client!)).Should()
            .BeEquivalentTo([CommonConstants.CommunicationManagementRole]);
    }

    [Fact]
    public async Task DeclaredServiceAccount_UnresolvableDeclaredRole_SkipsTheRemovalHalf()
    {
        // Half a declaration must not delete the surviving half: while any declared name cannot be
        // resolved (role seed pending), the sync only adds — the removal waits for a pass on which
        // the declaration is fully resolvable.
        await ArrangeAsync();
        var clientId = NewClientId();
        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-eight"));

        var request = BuildServiceAccountRequest(clientId, "plaintext-secret-eight");
        request.Clients = [request.Clients!.Single() with { AssignedRoleNames = ["NoSuchRoleYet"] }];
        await ConsumeAsync(request);

        var client = await LoadClientAsync(clientId);
        (await GetAssignedRoleNamesAsync(client!)).Should()
            .BeEquivalentTo([CommonConstants.CommunicationManagementRole]);
    }

    [Fact]
    public async Task ClientOutsideTheServiceAccountPrefix_KeepsTheAdditiveSemantics()
    {
        await ArrangeAsync();
        await EnsureRoleAsync("Ab5111ExtraRole");
        var clientId = $"legacy-client-{Guid.NewGuid():N}";

        var first = BuildServiceAccountRequest(clientId, "plaintext-secret-nine");
        first.Clients =
        [
            first.Clients!.Single() with
            {
                AssignedRoleNames = [CommonConstants.CommunicationManagementRole, "Ab5111ExtraRole"]
            }
        ];
        await ConsumeAsync(first);

        // A shrunken list on a NON-prefixed client must not remove anything — the pre-AB#5111
        // contract every other producer relies on.
        var second = BuildServiceAccountRequest(clientId, "plaintext-secret-nine");
        await ConsumeAsync(second);

        var client = await LoadClientAsync(clientId);
        (await GetAssignedRoleNamesAsync(client!)).Should()
            .BeEquivalentTo([CommonConstants.CommunicationManagementRole, "Ab5111ExtraRole"]);
    }

    // ---------- helpers ----------

    private string SystemTenantId => _fixture.GetSystemContext().TenantId;

    private static string NewClientId() => $"octo-pipeline-sa-{Guid.NewGuid():N}";

    private async Task ArrangeAsync()
    {
        await _fixture.InitializeAsync();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(SystemTenantId);
        // The role is created in-test rather than relied upon from the blueprint seed — same
        // convention as ClientRoleAssignmentIntegrationTests, so the assertions do not depend on
        // which entities the seed happens to provision in the fixture.
        await EnsureRoleAsync(CommonConstants.CommunicationManagementRole);
    }

    private async Task EnsureRoleAsync(string roleName)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();

        var existing = await repo.GetRtEntitiesByTypeAsync<RtRole>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals,
                roleName.ToUpperInvariant()));
        if (existing.Items.Any())
        {
            await session.CommitTransactionAsync();
            return;
        }

        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = roleName,
            NormalizedName = roleName.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
    }

    private CreateIdentityDataCommandRequest BuildServiceAccountRequest(string clientId, string? clientSecret)
    {
        return new CreateIdentityDataCommandRequest(SystemTenantId)
        {
            Clients =
            [
                new DistClientDto(clientId, "Pipeline service account", "https://communication.example.com")
                {
                    AllowedGrantTypes =
                        ["client_credentials", "urn:meshmakers:params:oauth:grant-type:on-behalf-of"],
                    RedirectUris = [],
                    PostLogoutRedirectUris = [],
                    AllowedCorsOrigins = [],
                    AllowedScopes = [CommonConstants.OctoApiFullAccess],
                    AllowOfflineAccess = false,
                    ClientSecret = clientSecret,
                    RequireClientSecret = true,
                    AssignedRoleNames = [CommonConstants.CommunicationManagementRole]
                }
            ]
        };
    }

    private async Task ConsumeAsync(CreateIdentityDataCommandRequest request)
    {
        var consumer = new CreateIdentityDataCommandRequestConsumer(
            NullLogger<CreateIdentityDataCommandRequestConsumer>.Instance,
            _fixture.GetSystemContext());
        var context = new RecordingContext(request);
        await consumer.ConsumeAsync(context);
        context.Response.Should().NotBeNull();
    }

    private async Task<RtClient?> LoadClientAsync(string clientId)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private async Task<IReadOnlyList<string>> GetAssignedRoleNamesAsync(RtClient client)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();

        var associations = await repo.GetRtAssociationsAsync(session,
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), client.RtId),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        var names = new List<string>();
        foreach (var association in associations.Items)
        {
            var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, association.TargetRtId);
            if (role?.Name != null)
            {
                names.Add(role.Name);
            }
        }

        return names;
    }

    /// <summary>
    /// The consumer only needs the message and a place to put its response; the bus itself is not
    /// under test here.
    /// </summary>
    private sealed class RecordingContext(CreateIdentityDataCommandRequest message)
        : IDistributedContext<CreateIdentityDataCommandRequest>
    {
        public CreateIdentityDataCommandRequest Message { get; } = message;

        public object? Response { get; private set; }

        public Task RespondAsync<T>(T responseMessage) where T : class
        {
            Response = responseMessage;
            return Task.CompletedTask;
        }

        public Task PublishAsync<T>(T publishedMessage) where T : class
        {
            return Task.CompletedTask;
        }
    }
}
