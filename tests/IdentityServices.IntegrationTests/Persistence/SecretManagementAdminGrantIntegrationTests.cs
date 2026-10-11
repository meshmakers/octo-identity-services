using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.SecretManagement;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#5544: the one-time grant of SecretManagement to existing tenant administrators, against a real MongoDB
///     (Testcontainers) — reads the role graph through the production read path, writes AssignedRole edges,
///     records the run-once marker, never removes anything. Each test uses its own child tenant. The fixture
///     does not register the System.Identity.Bootstrap blueprint catalog (Program.cs-only), so the roles and
///     the TenantOwners group are materialised in-test at their blueprint rtIds.
/// </summary>
[Collection("Sequential")]
public class SecretManagementAdminGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId TenantManagementRtId = new("660000000000000000000001");
    private static readonly OctoObjectId AdminPanelManagementRtId = new("660000000000000000000005");
    private static readonly OctoObjectId SecretManagementRtId = new("660000000000000000000060");

    private readonly IdentityServicesFixture _fixture;

    public SecretManagementAdminGrantIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ExistingHumanAdministrators_AreGrantedOnce_AdditiveOnly()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);

        var directAdmin = await InsertUserAsync(repo, "direct-admin");
        var adminPanelOnly = await InsertUserAsync(repo, "adminpanel-only");
        var groupMember = await InsertUserAsync(repo, "group-member");
        var owner = await InsertUserAsync(repo, "owner");
        // AB#5708: a provisioned parent-tenant administrator exists as an xt_ shadow user, a member of TenantOwners.
        var shadow = await InsertUserAsync(repo, "xt_parent_gerald");
        var serviceAccount = await InsertClientAsync(repo);
        var adminsGroup = await InsertGroupAsync(repo, OctoObjectId.GenerateNewId(), "admins");
        var owners = await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");

        await LinkAsync(repo, User(directAdmin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(directAdmin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(adminPanelOnly), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminsGroup), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminsGroup), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminsGroup), User(groupMember), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(adminsGroup), Client(serviceAccount), IdentityAssociationConstants.GroupMemberId);
        // TenantOwners holds every role (blueprint): its human member qualifies, the shadow user and the client do not.
        await LinkAsync(repo, Group(owners), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(owners), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(owners), User(owner), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(owners), User(shadow), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(owners), Client(serviceAccount), IdentityAssociationConstants.GroupMemberId);

        var result = await SecretManagementAdminGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        result.Status.Should().Be(SecretManagementAdminGrantStatus.Completed);
        result.GrantedUserIds.Should().BeEquivalentTo(
            new[] { directAdmin.ToString(), groupMember.ToString(), owner.ToString() });
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await HasSecretManagementAsync(repo, User(directAdmin))).Should().BeTrue("both roles held directly");
            (await HasSecretManagementAsync(repo, User(groupMember))).Should().BeTrue("a human holding both roles via a group");
            (await HasSecretManagementAsync(repo, User(owner))).Should().BeTrue("a human member of TenantOwners");
            (await HasSecretManagementAsync(repo, User(adminPanelOnly))).Should().BeFalse(
                "AdminPanelManagement alone does not grant secret sweeps");
            (await HasSecretManagementAsync(repo, User(shadow))).Should().BeFalse(
                "a provisioned parent-tenant administrator (xt_ shadow user) is not a local human administrator");
            (await HasSecretManagementAsync(repo, Client(serviceAccount))).Should().BeFalse("a client is no human");
            (await HasSecretManagementAsync(repo, Group(adminsGroup))).Should().BeFalse(
                "no group grant: clients and mappings in it would inherit the role");
            (await HasSecretManagementAsync(repo, Group(owners))).Should().BeFalse(
                "no TenantOwners edge: clients and provisioned administrators sit in it");
            (await HasRoleAsync(repo, User(directAdmin), TenantManagementRtId)).Should().BeTrue("nothing is removed");
            (await HasRoleAsync(repo, Group(adminsGroup), AdminPanelManagementRtId)).Should().BeTrue("nothing is removed");
        }

        // A second run with the marker present writes nothing; a concurrent duplicate cannot happen either.
        var edgesBefore = await CountSecretManagementEdgesAsync(repo, User(directAdmin));
        edgesBefore.Should().Be(1);

        // An operator removes the grant again — the next setup must not re-add it (run-once marker).
        await UnlinkAsync(repo, User(directAdmin), Role(SecretManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        var second = await SecretManagementAdminGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        second.Status.Should().Be(SecretManagementAdminGrantStatus.AlreadyDone);
        (await HasSecretManagementAsync(repo, User(directAdmin))).Should().BeFalse();
    }

    [Fact]
    public async Task ConcurrentRuns_WriteExactlyOneEdgePerAdministrator()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var admin = await InsertUserAsync(repo, "admin");
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        // Setup, tenant update and the failed-tenant retry can reach the same tenant at the same moment.
        var results = await Task.WhenAll(Enumerable.Range(0, 6)
            .Select(_ => Task.Run(() => SecretManagementAdminGrant.EnsureAsync(tenantContext, NullLogger.Instance))));

        results.Count(r => r.Status == SecretManagementAdminGrantStatus.Completed).Should().Be(1);
        results.Count(r => r.Status == SecretManagementAdminGrantStatus.AlreadyDone).Should().Be(5);
        (await CountSecretManagementEdgesAsync(repo, User(admin))).Should().Be(1, "the engine would accept duplicates");
    }

    [Fact]
    public async Task RoleMissing_WritesNothingAndNoMarker_ThenRunsOnceTheRoleExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        var admin = await InsertUserAsync(repo, "admin");
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        var first = await SecretManagementAdminGrant.EnsureAsync(tenantContext, NullLogger.Instance);
        first.Status.Should().Be(SecretManagementAdminGrantStatus.RoleMissing);

        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var second = await SecretManagementAdminGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        second.Status.Should().Be(SecretManagementAdminGrantStatus.Completed,
            "no marker may be recorded while the role is missing");
        second.GrantedUserIds.Should().Equal(admin.ToString());
        (await HasSecretManagementAsync(repo, User(admin))).Should().BeTrue();
    }

    [Fact]
    public async Task TenantSetup_RunsTheGrant_AfterTheRoleExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var admin = await InsertUserAsync(repo, "admin");
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        // The production trigger: identity startup / PosUpdateTenant run SetupAsync for every tenant.
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);

        (await HasSecretManagementAsync(repo, User(admin))).Should().BeTrue();
        using var session = await tenantContext.GetAdminSessionAsync();
        var marker = await tenantContext.GetConfigurationAsync<SecretManagementAdminGrantMarker>(
            session, IdentityServiceConstants.SecretManagementAdminGrantKey, defaultValue: null);
        marker.Should().NotBeNull();
        marker!.GrantedUserIds.Should().Equal(admin.ToString());
    }

    // ---------- helpers ----------

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"smgrant-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        // Imports the Identity CK model; without the blueprint catalog the SecretManagement role does not
        // exist yet, so the grant step inside the setup ends as RoleMissing and records no marker.
        await setup.SetupAsync(tenantId);

        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        var repo = tenantContext.GetTenantRepositoryAsAdmin();

        using var check = await repo.GetSessionAsync();
        check.StartTransaction();
        var roles = await repo.GetRtEntitiesByTypeAsync<RtRole>(check, RtEntityQueryOptions.Create());
        await check.CommitTransactionAsync();
        roles.Items.Should().NotContain(r => r.Name == CommonConstants.SecretManagementRole,
            "precondition: the fixture seeds no blueprint roles; if it starts to, the marker is already set and " +
            "these tests must arrange differently");

        return (tenantContext, repo);
    }

    private static RtEntityId User(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtUser>(), id);
    private static RtEntityId Group(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), id);
    private static RtEntityId Role(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtRole>(), id);
    private static RtEntityId Client(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtClient>(), id);

    private static readonly OctoObjectId TenantOwnersRtId = new("660000000000000000000040");

    private static async Task InsertRoleAsync(ITenantRepository repo, OctoObjectId rtId, string name)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = rtId, Name = name, NormalizedName = name.ToUpperInvariant(), RtWellKnownName = name
        });
        await session.CommitTransactionAsync();
    }

    private static async Task<OctoObjectId> InsertUserAsync(ITenantRepository repo, string prefix)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var userName = $"{prefix}-{Guid.NewGuid():N}";
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtUser
        {
            RtId = rtId,
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = $"{userName}@example.com",
            NormalizedEmail = $"{userName}@example.com".ToUpperInvariant(),
            SecurityStamp = Guid.NewGuid().ToString()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> InsertGroupAsync(ITenantRepository repo, OctoObjectId rtId, string name)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtGroup
        {
            RtId = rtId, GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static Task LinkAsync(
        ITenantRepository repo, RtEntityId origin, RtEntityId target, RtCkId<CkAssociationRoleId> roleId) =>
        ApplyAsync(repo, AssociationUpdateInfo.CreateInsert(origin, target, roleId));

    private static Task UnlinkAsync(
        ITenantRepository repo, RtEntityId origin, RtEntityId target, RtCkId<CkAssociationRoleId> roleId) =>
        ApplyAsync(repo, AssociationUpdateInfo.CreateDelete(origin, target, roleId));

    private static async Task ApplyAsync(ITenantRepository repo, AssociationUpdateInfo update)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.ApplyChangesAsync(session, new[] { update }, new OperationResult());
        await session.CommitTransactionAsync();
    }

    private static async Task<OctoObjectId> InsertClientAsync(ITenantRepository repo)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = true,
            ClientId = $"octo-pipeline-sa-{Guid.NewGuid():N}",
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
            AllowedScopes = new AttributeStringValueList { "octo_api" }
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<int> CountSecretManagementEdgesAsync(ITenantRepository repo, RtEntityId origin)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var edges = await repo.GetRtAssociationsAsync(session, origin,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        await session.CommitTransactionAsync();
        return edges.Items.Count(e => e.TargetRtId == SecretManagementRtId);
    }

    private static Task<bool> HasSecretManagementAsync(ITenantRepository repo, RtEntityId origin) =>
        HasRoleAsync(repo, origin, SecretManagementRtId);

    private static async Task<bool> HasRoleAsync(ITenantRepository repo, RtEntityId origin, OctoObjectId roleRtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var edges = await repo.GetRtAssociationsAsync(session, origin,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        await session.CommitTransactionAsync();
        return edges.Items.Any(e => e.TargetRtId == roleRtId);
    }
}
