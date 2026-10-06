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
    public async Task ExistingAdministrators_AreGrantedOnce_AdditiveOnly()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);

        var directAdmin = await InsertUserAsync(repo, "direct-admin");
        var adminPanelOnly = await InsertUserAsync(repo, "adminpanel-only");
        var groupMember = await InsertUserAsync(repo, "group-member");
        var owner = await InsertUserAsync(repo, "owner");
        var adminsGroup = await InsertGroupAsync(repo, OctoObjectId.GenerateNewId(), "admins");
        var owners = await InsertGroupAsync(repo, SecretManagementAdminGrant.TenantOwnersGroupRtId, "TenantOwners");

        await LinkAsync(repo, User(directAdmin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(directAdmin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(adminPanelOnly), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminsGroup), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminsGroup), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(adminsGroup), User(groupMember), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(owners), User(owner), IdentityAssociationConstants.GroupMemberId);

        var result = await SecretManagementAdminGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        result.Status.Should().Be(SecretManagementAdminGrantStatus.Completed);
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await HasSecretManagementAsync(repo, User(directAdmin))).Should().BeTrue("both roles held directly");
            (await HasSecretManagementAsync(repo, User(adminPanelOnly))).Should().BeFalse(
                "AdminPanelManagement alone does not grant secret sweeps");
            (await HasSecretManagementAsync(repo, Group(adminsGroup))).Should().BeTrue("the roles come from the group");
            (await HasSecretManagementAsync(repo, User(groupMember))).Should().BeFalse(
                "the member receives it through the group, not as a direct edge");
            (await HasSecretManagementAsync(repo, Group(owners))).Should().BeTrue("TenantOwners always gets it");
            (await HasSecretManagementAsync(repo, User(owner))).Should().BeFalse();
            (await HasRoleAsync(repo, User(directAdmin), TenantManagementRtId)).Should().BeTrue("nothing is removed");
            (await HasRoleAsync(repo, Group(adminsGroup), AdminPanelManagementRtId)).Should().BeTrue("nothing is removed");
        }

        // An operator removes the grant again — the next setup must not re-add it (run-once marker).
        await UnlinkAsync(repo, User(directAdmin), Role(SecretManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        var second = await SecretManagementAdminGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        second.Status.Should().Be(SecretManagementAdminGrantStatus.AlreadyDone);
        (await HasSecretManagementAsync(repo, User(directAdmin))).Should().BeFalse();
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
