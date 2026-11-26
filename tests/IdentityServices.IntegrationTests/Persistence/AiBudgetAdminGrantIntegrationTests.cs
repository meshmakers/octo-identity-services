using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.RoleGrants;
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
///     The one-time grant of the platform role AiBudgetAdmin to the human administrators of the SYSTEM tenant,
///     against a real MongoDB. Each test uses its own child tenant; "system tenant" is simulated by passing that tenant's
///     id as the system tenant id (the grant compares the two), "child tenant" by passing another id. The roles and the
///     TenantOwners group are materialised in-test at their blueprint rtIds (the fixture has no blueprint catalog).
/// </summary>
[Collection("Sequential")]
public class AiBudgetAdminGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId TenantManagementRtId = new("660000000000000000000001");
    private static readonly OctoObjectId AdminPanelManagementRtId = new("660000000000000000000005");
    private static readonly OctoObjectId AiBudgetAdminRtId = new("660000000000000000000063");
    private static readonly OctoObjectId TenantOwnersRtId = new("660000000000000000000040");

    private readonly IdentityServicesFixture _fixture;

    public AiBudgetAdminGrantIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task SystemTenant_HumanAdministratorsAreGrantedOnce_NoGroupClientOrShadowUser()
    {
        var (tenantContext, repo, admins) = await ArrangeTenantAsync();

        var result = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);

        result.Status.Should().Be(AdministratorRoleGrantStatus.Completed);
        result.GrantedUserIds.Should().BeEquivalentTo(new[] { admins.DirectAdmin.ToString(), admins.Owner.ToString() });
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await HasBudgetRoleAsync(repo, User(admins.DirectAdmin))).Should().BeTrue("both admin roles held directly");
            (await HasBudgetRoleAsync(repo, User(admins.Owner))).Should().BeTrue("a human member of TenantOwners");
            (await HasBudgetRoleAsync(repo, User(admins.AdminPanelOnly))).Should().BeFalse(
                "AdminPanelManagement alone is no administrator");
            (await HasBudgetRoleAsync(repo, User(admins.Shadow))).Should().BeFalse(
                "a provisioned parent-tenant administrator (xt_ shadow user) is no local human administrator");
            (await HasBudgetRoleAsync(repo, Client(admins.ServiceAccount))).Should().BeFalse("never a client");
            (await HasBudgetRoleAsync(repo, Group(TenantOwnersRtId))).Should().BeFalse(
                "never TenantOwners: its clients and provisioned administrators would inherit it");
        }

        var marker = await ReadMarkerAsync(tenantContext);
        marker.Should().NotBeNull();
        marker!.GrantedUserIds.Should().BeEquivalentTo(new[] { admins.DirectAdmin.ToString(), admins.Owner.ToString() });

        // Run-once: a re-run is a no-op, and a grant an operator removed does not come back.
        await UnlinkAsync(repo, User(admins.DirectAdmin), Role(AiBudgetAdminRtId), IdentityAssociationConstants.AssignedRoleId);
        var second = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);

        second.Status.Should().Be(AdministratorRoleGrantStatus.AlreadyDone);
        second.GrantedUserIds.Should().BeEmpty();
        (await HasBudgetRoleAsync(repo, User(admins.DirectAdmin))).Should().BeFalse();
        (await CountBudgetEdgesAsync(repo, User(admins.Owner))).Should().Be(1, "no second edge on a re-run");
    }

    [Fact]
    public async Task ChildTenant_NobodyIsGranted_AndNoMarkerIsWritten()
    {
        var (tenantContext, repo, admins) = await ArrangeTenantAsync();

        var result = await AiBudgetAdminGrant.EnsureAsync(tenantContext, $"other-{Guid.NewGuid():N}", NullLogger.Instance);

        result.Status.Should().Be(AdministratorRoleGrantStatus.NotApplicable);
        result.GrantedUserIds.Should().BeEmpty();
        (await HasBudgetRoleAsync(repo, User(admins.DirectAdmin))).Should().BeFalse("child-tenant administrators never get it");
        (await HasBudgetRoleAsync(repo, User(admins.Owner))).Should().BeFalse();
        (await HasBudgetRoleAsync(repo, Group(TenantOwnersRtId))).Should().BeFalse();
        (await ReadMarkerAsync(tenantContext)).Should().BeNull("a child tenant records nothing");
    }

    [Fact]
    public async Task SystemTenant_WithoutTheRole_IsRetriedLater()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        var admin = await InsertUserAsync(repo, "admin");
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        var first = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);
        first.Status.Should().Be(AdministratorRoleGrantStatus.RoleMissing);
        (await ReadMarkerAsync(tenantContext)).Should().BeNull("blueprint 1.11.0 not applied yet: retried next setup");

        await InsertRoleAsync(repo, AiBudgetAdminRtId, IdentityServiceConstants.AiBudgetAdminRole);
        var second = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);

        second.Status.Should().Be(AdministratorRoleGrantStatus.Completed);
        (await HasBudgetRoleAsync(repo, User(admin))).Should().BeTrue();
    }

    [Fact]
    public async Task SystemTenant_WithoutAnAdministratorYet_WritesNoMarker_AndGrantsTheFirstOneLater()
    {
        // Fresh installation: the system tenant is set up before its first administrator exists.
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, AiBudgetAdminRtId, IdentityServiceConstants.AiBudgetAdminRole);

        var first = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);
        first.Status.Should().Be(AdministratorRoleGrantStatus.NoAdministratorYet);
        (await ReadMarkerAsync(tenantContext)).Should().BeNull("otherwise the first administrator would never get it");

        var admin = await InsertUserAsync(repo, "first-admin");
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        var second = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);

        second.Status.Should().Be(AdministratorRoleGrantStatus.Completed);
        second.GrantedUserIds.Should().Equal(admin.ToString());
        (await ReadMarkerAsync(tenantContext)).Should().NotBeNull();
    }

    [Fact]
    public async Task SystemTenant_GrantCommittedButMarkerMissing_WritesTheMarker_AndNeverGrantsAgain()
    {
        // The edges of an earlier run were committed, but its marker write failed (pod killed, failover).
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, AiBudgetAdminRtId, IdentityServiceConstants.AiBudgetAdminRole);
        var admin = await InsertUserAsync(repo, "granted-admin");
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(AiBudgetAdminRtId), IdentityAssociationConstants.AssignedRoleId);

        var first = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);

        first.Status.Should().Be(AdministratorRoleGrantStatus.Completed, "every administrator already holds the role");
        first.GrantedUserIds.Should().BeEmpty();
        (await ReadMarkerAsync(tenantContext)).Should().NotBeNull("the step is done; otherwise it would run forever");

        // An operator removes the role, and a new administrator joins: neither gets it from setup.
        await UnlinkAsync(repo, User(admin), Role(AiBudgetAdminRtId), IdentityAssociationConstants.AssignedRoleId);
        var newcomer = await InsertUserAsync(repo, "new-admin");
        await LinkAsync(repo, User(newcomer), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(newcomer), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        var second = await AiBudgetAdminGrant.EnsureAsync(tenantContext, tenantContext.TenantId, NullLogger.Instance);

        second.Status.Should().Be(AdministratorRoleGrantStatus.AlreadyDone);
        (await HasBudgetRoleAsync(repo, User(admin))).Should().BeFalse();
        (await HasBudgetRoleAsync(repo, User(newcomer))).Should().BeFalse();
    }

    private sealed record Admins(
        OctoObjectId DirectAdmin, OctoObjectId Owner, OctoObjectId AdminPanelOnly, OctoObjectId Shadow,
        OctoObjectId ServiceAccount);

    private async Task<(ITenantContext, ITenantRepository, Admins)> ArrangeTenantAsync()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, AdminPanelManagementRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, AiBudgetAdminRtId, IdentityServiceConstants.AiBudgetAdminRole);

        var directAdmin = await InsertUserAsync(repo, "direct-admin");
        var owner = await InsertUserAsync(repo, "owner");
        var adminPanelOnly = await InsertUserAsync(repo, "adminpanel-only");
        var shadow = await InsertUserAsync(repo, "xt_parent_admin");
        var serviceAccount = await InsertClientAsync(repo);
        await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");

        await LinkAsync(repo, User(directAdmin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(directAdmin), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(adminPanelOnly), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(TenantOwnersRtId), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(TenantOwnersRtId), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(TenantOwnersRtId), User(owner), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(TenantOwnersRtId), User(shadow), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(TenantOwnersRtId), Client(serviceAccount), IdentityAssociationConstants.GroupMemberId);
        // A client that holds both admin roles directly is still no human administrator.
        await LinkAsync(repo, Client(serviceAccount), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Client(serviceAccount), Role(AdminPanelManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        return (tenantContext, repo, new Admins(directAdmin, owner, adminPanelOnly, shadow, serviceAccount));
    }

    private async Task<(ITenantContext, ITenantRepository)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"aibgrant-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        // Imports the Identity CK model. The setup of a child tenant never runs the AiBudgetAdmin grant (not the
        // system tenant), so no marker exists before the test calls the grant itself.
        await setup.SetupAsync(tenantId);

        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        return (tenantContext, tenantContext.GetTenantRepositoryAsAdmin());
    }

    private static async Task<AiBudgetAdminGrantMarker?> ReadMarkerAsync(ITenantContext tenantContext)
    {
        using var session = await tenantContext.GetAdminSessionAsync();
        return await tenantContext.GetConfigurationAsync<AiBudgetAdminGrantMarker>(
            session, IdentityServiceConstants.AiBudgetAdminGrantKey, defaultValue: null);
    }

    private static RtEntityId User(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtUser>(), id);
    private static RtEntityId Group(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), id);
    private static RtEntityId Role(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtRole>(), id);
    private static RtEntityId Client(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtClient>(), id);

    private static async Task InsertRoleAsync(ITenantRepository repo, OctoObjectId rtId, string name)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = rtId,
            Name = name,
            NormalizedName = name.ToUpperInvariant(),
            RtWellKnownName = name
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

    private static async Task InsertGroupAsync(ITenantRepository repo, OctoObjectId rtId, string name)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtGroup
        {
            RtId = rtId,
            GroupName = name,
            NormalizedGroupName = name.ToUpperInvariant()
        });
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

    private static async Task<int> CountBudgetEdgesAsync(ITenantRepository repo, RtEntityId origin)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var edges = await repo.GetRtAssociationsAsync(session, origin,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        await session.CommitTransactionAsync();
        return edges.Items.Count(e => e.TargetRtId == AiBudgetAdminRtId);
    }

    private static async Task<bool> HasBudgetRoleAsync(ITenantRepository repo, RtEntityId origin) =>
        await CountBudgetEdgesAsync(repo, origin) > 0;
}
