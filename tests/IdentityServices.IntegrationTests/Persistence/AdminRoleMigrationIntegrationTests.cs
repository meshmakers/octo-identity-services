using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.AdminRoleMigration;
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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#8165: the admin role migration (Off / DryRun / Apply) against a real MongoDB (Testcontainers). Each test
///     uses its own child tenant; roles and the TenantOwners group are materialised in-test at their blueprint rtIds.
/// </summary>
[Collection("Sequential")]
public class AdminRoleMigrationIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId TenantManagementRtId = new("660000000000000000000001");
    private static readonly OctoObjectId UserManagementRtId = new("660000000000000000000002");
    private static readonly OctoObjectId DevelopmentRtId = new("660000000000000000000003");
    private static readonly OctoObjectId SecretManagementRtId = new("660000000000000000000060");

    private readonly IdentityServicesFixture _fixture;

    public AdminRoleMigrationIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    private async Task<(ITenantContext Ctx, ITenantRepository Repo, OctoObjectId Owners, OctoObjectId CustomRole)>
        ArrangeAsync(bool ownersCarryAdminRoles = true)
    {
        var (ctx, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, UserManagementRtId, CommonConstants.UserManagementRole);
        await InsertRoleAsync(repo, DevelopmentRtId, CommonConstants.DevelopmentRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var custom = OctoObjectId.GenerateNewId();
        await InsertRoleAsync(repo, custom, "CustomRole");
        var owners = await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");
        if (ownersCarryAdminRoles)
        {
            foreach (var role in new[] { TenantManagementRtId, UserManagementRtId, DevelopmentRtId, SecretManagementRtId })
            {
                await LinkAsync(repo, Group(owners), Role(role), IdentityAssociationConstants.AssignedRoleId);
            }
        }

        return (ctx, repo, owners, custom);
    }

    private static async Task GrantAsync(ITenantRepository repo, RtEntityId subject, params OctoObjectId[] roles)
    {
        foreach (var role in roles)
        {
            await LinkAsync(repo, subject, Role(role), IdentityAssociationConstants.AssignedRoleId);
        }
    }

    private static async Task<bool> IsMemberAsync(ITenantRepository repo, OctoObjectId owners, RtEntityId subject)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var edges = await repo.GetRtAssociationsAsync(session, Group(owners),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.GroupMemberId));
        await session.CommitTransactionAsync();
        return edges.Items.Any(e => e.TargetRtId == subject.RtId);
    }

    [Fact]
    public async Task Apply_FullyCovered_UserJoinsAndLosesTheCoveredRoles_PartlyCovered_KeepsTheOthers()
    {
        var (ctx, repo, owners, custom) = await ArrangeAsync();
        var full = await InsertUserAsync(repo, "full");
        var partly = await InsertUserAsync(repo, "partly");
        var shadow = await InsertUserAsync(repo, "xt_parent_admin");
        var tmOnly = await InsertUserAsync(repo, "tmonly");
        await GrantAsync(repo, User(full), TenantManagementRtId, UserManagementRtId, DevelopmentRtId);
        await GrantAsync(repo, User(partly), TenantManagementRtId, UserManagementRtId, custom);
        await GrantAsync(repo, User(shadow), TenantManagementRtId, UserManagementRtId);
        await GrantAsync(repo, User(tmOnly), TenantManagementRtId);

        var result = await TenantAdminRoleMigration.EnsureAsync(ctx, AdminRoleMigrationMode.Apply, NullLogger.Instance);

        result.Status.Should().Be(AdminRoleMigrationStatus.Applied);
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await IsMemberAsync(repo, owners, User(full))).Should().BeTrue();
            (await HasRoleAsync(repo, User(full), TenantManagementRtId)).Should().BeFalse("covered by the group");
            (await HasRoleAsync(repo, User(full), DevelopmentRtId)).Should().BeFalse("covered by the group");
            (await IsMemberAsync(repo, owners, User(partly))).Should().BeTrue();
            (await HasRoleAsync(repo, User(partly), TenantManagementRtId)).Should().BeFalse();
            (await HasRoleAsync(repo, User(partly), custom)).Should().BeTrue("a role the group does not carry stays");
            (await IsMemberAsync(repo, owners, User(shadow))).Should().BeTrue("xt_ users are migrated");
            (await IsMemberAsync(repo, owners, User(tmOnly))).Should().BeFalse("TenantManagement alone does not qualify");
            (await HasRoleAsync(repo, User(tmOnly), TenantManagementRtId)).Should().BeTrue();
        }
    }

    [Fact]
    public async Task Apply_Mapping_JoinsAndLosesCoveredRoleIds_ClientsAndGroupsAreNotMigrated()
    {
        var (ctx, repo, owners, custom) = await ArrangeAsync();
        var mapping = await InsertMappingAsync(repo, "octosystem", TenantManagementRtId, UserManagementRtId, custom);
        var client = await InsertClientAsync(repo);
        await GrantAsync(repo, Client(client), TenantManagementRtId, UserManagementRtId);
        var otherGroup = await InsertGroupAsync(repo, OctoObjectId.GenerateNewId(), "others");
        await GrantAsync(repo, Group(otherGroup), TenantManagementRtId, UserManagementRtId);

        await TenantAdminRoleMigration.EnsureAsync(ctx, AdminRoleMigrationMode.Apply, NullLogger.Instance);

        var mappingEntity = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtExternalTenantUserMapping>(), mapping);
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await IsMemberAsync(repo, owners, mappingEntity)).Should().BeTrue();
            (await MappedRolesAsync(repo, mapping)).Should().BeEquivalentTo(new[] { custom.ToString() });
            (await HasRoleAsync(repo, Client(client), TenantManagementRtId)).Should().BeTrue("clients are not migrated");
            (await IsMemberAsync(repo, owners, Client(client))).Should().BeFalse();
            (await HasRoleAsync(repo, Group(otherGroup), TenantManagementRtId)).Should().BeTrue("groups are not migrated");
        }
    }

    [Fact]
    public async Task DryRun_ReportsThePlan_AndWritesNothing()
    {
        var (ctx, repo, owners, _) = await ArrangeAsync();
        var admin = await InsertUserAsync(repo, "admin");
        await GrantAsync(repo, User(admin), TenantManagementRtId, UserManagementRtId);

        var result = await TenantAdminRoleMigration.EnsureAsync(ctx, AdminRoleMigrationMode.DryRun, NullLogger.Instance);

        result.Status.Should().Be(AdminRoleMigrationStatus.DryRun);
        result.Plan.Should().ContainSingle().Which.RtId.Should().Be(admin.ToString());
        (await IsMemberAsync(repo, owners, User(admin))).Should().BeFalse();
        (await HasRoleAsync(repo, User(admin), TenantManagementRtId)).Should().BeTrue();
    }

    [Fact]
    public async Task Off_ReadsAndWritesNothing()
    {
        var (ctx, repo, owners, _) = await ArrangeAsync();
        var admin = await InsertUserAsync(repo, "admin");
        await GrantAsync(repo, User(admin), TenantManagementRtId, UserManagementRtId);

        var result = await TenantAdminRoleMigration.EnsureAsync(ctx, AdminRoleMigrationMode.Off, NullLogger.Instance);

        result.Status.Should().Be(AdminRoleMigrationStatus.Skipped);
        (await IsMemberAsync(repo, owners, User(admin))).Should().BeFalse();
        (await HasRoleAsync(repo, User(admin), TenantManagementRtId)).Should().BeTrue();
    }

    [Fact]
    public async Task Apply_IsIdempotent_ASecondRunPlansAndChangesNothing()
    {
        var (ctx, repo, owners, custom) = await ArrangeAsync();
        var admin = await InsertUserAsync(repo, "admin");
        await GrantAsync(repo, User(admin), TenantManagementRtId, UserManagementRtId, custom);

        await TenantAdminRoleMigration.EnsureAsync(ctx, AdminRoleMigrationMode.Apply, NullLogger.Instance);
        var second = await TenantAdminRoleMigration.EnsureAsync(ctx, AdminRoleMigrationMode.Apply, NullLogger.Instance);

        second.Plan.Should().BeEmpty();
        (await IsMemberAsync(repo, owners, User(admin))).Should().BeTrue();
        (await HasRoleAsync(repo, User(admin), custom)).Should().BeTrue();
    }

    [Fact]
    public async Task GroupWithoutAdminRoles_MigratesNothing_BecauseTheMoveWouldRemoveAccess()
    {
        var (ctx, repo, owners, _) = await ArrangeAsync(ownersCarryAdminRoles: false);
        var admin = await InsertUserAsync(repo, "admin");
        await GrantAsync(repo, User(admin), TenantManagementRtId, UserManagementRtId);

        var result = await TenantAdminRoleMigration.EnsureAsync(ctx, AdminRoleMigrationMode.Apply, NullLogger.Instance);

        result.Status.Should().Be(AdminRoleMigrationStatus.NotApplicable);
        (await IsMemberAsync(repo, owners, User(admin))).Should().BeFalse();
        (await HasRoleAsync(repo, User(admin), TenantManagementRtId)).Should().BeTrue();
    }

    // ---------- helpers ----------

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"adminmig-{Guid.NewGuid():N}"[..24];
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

    private static async Task<OctoObjectId> InsertMappingAsync(
        ITenantRepository repo, string sourceTenantId, params OctoObjectId[] roleIds)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
        {
            RtId = rtId,
            SourceTenantId = sourceTenantId,
            SourceUserId = Guid.NewGuid().ToString("N"),
            SourceUserName = $"user-{Guid.NewGuid():N}",
            MappedRoleIds = new AttributeStringValueList(roleIds.Select(r => r.ToString()).ToList())
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<List<string>> MappedRolesAsync(ITenantRepository repo, OctoObjectId mappingId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var mapping = await repo.GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mappingId);
        await session.CommitTransactionAsync();
        return mapping!.MappedRoleIds?.ToList() ?? [];
    }
}
