using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// End-to-end checks of Client role / group assignment (AB#4183) against a real MongoDB
/// (Testcontainers) with the full Octo runtime engine. Pins the behaviour the
/// <c>client_credentials</c> token-claim injection depends on: a client's effective role set
/// resolves direct <c>AssignedRole</c> assignments plus roles inherited via group membership —
/// the same machinery users use. Roles/clients/groups are created in-test so the assertions do
/// not depend on which entities the blueprint seed provisions in the fixture.
/// </summary>
public class ClientRoleAssignmentIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ClientRoleAssignmentIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task AddRoleToClient_DirectRole_AppearsInEffectiveRoleNames()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (clientRoleStore, _, repo) = CreateStores();

        var roleName = NewId("rA");
        var roleRtId = await CreateRoleAsync(repo, roleName);
        var clientRtId = await CreateClientAsync(repo, NewId("role"));

        await clientRoleStore.AddRoleAsync(clientRtId, roleName);

        var direct = await clientRoleStore.GetDirectRoleIdsAsync(clientRtId);
        var effective = await clientRoleStore.GetEffectiveRoleNamesAsync(clientRtId);

        direct.Should().Contain(roleRtId.ToString());
        effective.Should().Contain(roleName);
    }

    /// <summary>
    ///     AB#7928: <c>ApplyRoleChangesAsync</c> writes only the given additions and removals. A role it was not asked to
    ///     add is never inserted, so a role removed by a concurrent request is not restored behind the guard's back.
    /// </summary>
    [Fact]
    public async Task ApplyRoleChanges_WritesOnlyTheGivenDifference_AndNeverRestoresAnUnlistedRole()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (clientRoleStore, _, repo) = CreateStores();

        var kept = await CreateRoleAsync(repo, NewId("rKeep"));
        var removed = await CreateRoleAsync(repo, NewId("rRemove"));
        var added = await CreateRoleAsync(repo, NewId("rAdd"));
        var vanished = await CreateRoleAsync(repo, NewId("rVanished"));
        var clientRtId = await CreateClientAsync(repo, NewId("apply"));
        await clientRoleStore.SetRoleIdsAsync(clientRtId, [kept.ToString(), removed.ToString()]);

        // "vanished" is neither held nor listed as an addition: it must not appear; removing a role the client does not
        // hold and adding one it already holds are no-ops
        await clientRoleStore.ApplyRoleChangesAsync(clientRtId, [added.ToString(), kept.ToString()],
            [removed.ToString(), vanished.ToString()]);

        (await clientRoleStore.GetDirectRoleIdsAsync(clientRtId)).Should()
            .BeEquivalentTo(kept.ToString(), added.ToString());
    }

    [Fact]
    public async Task AddClientToGroup_InheritsGroupRole_ViaEffectiveRoleNames()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (clientRoleStore, groupStore, repo) = CreateStores();

        var roleName = NewId("rB");
        var roleRtId = await CreateRoleAsync(repo, roleName);
        var clientRtId = await CreateClientAsync(repo, NewId("grpc"));
        var groupRtId = await CreateGroupAsync(repo, NewId("g"));

        await groupStore.SetRoleIdsAsync(groupRtId, new[] { roleRtId.ToString() });
        await groupStore.AddMemberClientAsync(groupRtId, clientRtId.ToString());

        var direct = await clientRoleStore.GetDirectRoleIdsAsync(clientRtId);
        var effective = await clientRoleStore.GetEffectiveRoleNamesAsync(clientRtId);

        // Role is inherited via the group, NOT a direct assignment on the client.
        direct.Should().NotContain(roleRtId.ToString());
        effective.Should().Contain(roleName);
        (await groupStore.GetMemberClientIdsAsync(groupRtId)).Should().Contain(clientRtId.ToString());
    }

    [Fact]
    public async Task RemoveRoleFromClient_DropsRoleFromEffective()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (clientRoleStore, _, repo) = CreateStores();

        var roleName = NewId("rC");
        await CreateRoleAsync(repo, roleName);
        var clientRtId = await CreateClientAsync(repo, NewId("rem"));

        await clientRoleStore.AddRoleAsync(clientRtId, roleName);
        (await clientRoleStore.GetEffectiveRoleNamesAsync(clientRtId)).Should().Contain(roleName);

        await clientRoleStore.RemoveRoleAsync(clientRtId, roleName);

        (await clientRoleStore.GetEffectiveRoleNamesAsync(clientRtId)).Should().NotContain(roleName);
        (await clientRoleStore.GetDirectRoleIdsAsync(clientRtId)).Should().BeEmpty();
    }

    // ---------- helpers ----------

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private (ClientRoleStore clientRoleStore, GroupStore groupStore, ITenantRepository repo) CreateStores()
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        var resolver = new FixedTenantResolver(repo);
        var groupStore = new GroupStore(resolver);
        var groupRoleResolver = new GroupRoleResolver(groupStore, new ExternalTenantUserMappingStore(resolver), new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext()));
        var clientRoleStore = new ClientRoleStore(
            resolver, groupRoleResolver, NullLogger<ClientRoleStore>.Instance);
        return (clientRoleStore, groupStore, repo);
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

    private static async Task<OctoObjectId> CreateClientAsync(ITenantRepository repo, string clientId)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = true,
            ClientId = clientId,
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
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
}
