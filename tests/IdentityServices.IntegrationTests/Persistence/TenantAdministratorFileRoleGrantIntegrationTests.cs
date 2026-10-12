using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.FileRoles;
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
///     AB#6578: the one-time grant of FileManagement to the human tenant administrators (users holding
///     AdminPanelManagement AND TenantManagement), against a real MongoDB (Testcontainers). Covers the tenant that
///     already carries the Reporting-based FileRoleGrant marker (the bad test-2 tenants), exclusion of shadow users,
///     groups, clients and mappings, idempotency and the separate run-once marker. Each test uses its own child tenant.
/// </summary>
[Collection("Sequential")]
public class TenantAdministratorFileRoleGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId ReportingManagementRtId = new("660000000000000000000009");
    private static readonly OctoObjectId ReportingViewerRtId = new("66000000000000000000000A");
    private static readonly OctoObjectId FileManagementRtId = new("660000000000000000000061");
    private static readonly OctoObjectId FileViewerRtId = new("660000000000000000000062");
    private static readonly OctoObjectId TenantManagementRtId = new("660000000000000000000001");
    private static readonly OctoObjectId AdminPanelRtId = new("660000000000000000000002");
    private static readonly OctoObjectId DevelopmentRtId = new("660000000000000000000004");

    private readonly IdentityServicesFixture _fixture;

    public TenantAdministratorFileRoleGrantIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task HumanAdmins_GetFileManagementOnce_EvenWhenTheReportingMarkerAlreadyExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertAllRolesAsync(repo);

        // The bad test-2 tenants: the Reporting-based grant ran (marker present) but there was nobody to grant.
        using (var markerSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(markerSession, IdentityServiceConstants.FileRoleGrantKey,
                new FileRoleGrantMarker { CompletedAtUtc = DateTime.UtcNow });
        }

        var direct = await InsertUserAsync(repo, "direct");
        var viaGroup = await InsertUserAsync(repo, "viagroup");
        var panelOnly = await InsertUserAsync(repo, "panelonly");
        var shadow = await InsertShadowUserAsync(repo);
        var alreadyHas = await InsertUserAsync(repo, "alreadyhas");
        var owners = await InsertGroupAsync(repo, "owners");
        var serviceAccount = await InsertClientAsync(repo, "svc");
        var mapping = await InsertMappingAsync(repo, [AdminPanelRtId.ToString(), TenantManagementRtId.ToString()]);

        var assigned = IdentityAssociationConstants.AssignedRoleId;
        await LinkAsync(repo, User(direct), Role(AdminPanelRtId), assigned);
        await LinkAsync(repo, User(direct), Role(TenantManagementRtId), assigned);
        await LinkAsync(repo, Group(owners), Role(AdminPanelRtId), assigned);
        await LinkAsync(repo, Group(owners), Role(TenantManagementRtId), assigned);
        await LinkAsync(repo, Group(owners), User(viaGroup), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(owners), User(shadow), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Group(owners), Client(serviceAccount), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, User(panelOnly), Role(AdminPanelRtId), assigned);
        await LinkAsync(repo, User(alreadyHas), Role(AdminPanelRtId), assigned);
        await LinkAsync(repo, User(alreadyHas), Role(TenantManagementRtId), assigned);
        await LinkAsync(repo, User(alreadyHas), Role(FileManagementRtId), assigned);

        var result = await TenantAdministratorFileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        result.Status.Should().Be(TenantAdministratorFileRoleGrantStatus.Completed);
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await HasRoleAsync(repo, User(direct), FileManagementRtId)).Should().BeTrue("holds both admin roles directly");
            (await HasRoleAsync(repo, User(viaGroup), FileManagementRtId)).Should().BeTrue("holds both through TenantOwners-like group; granted as a direct edge");
            (await HasRoleAsync(repo, User(panelOnly), FileManagementRtId)).Should().BeFalse("AdminPanelManagement alone is not tenant administration");
            (await HasRoleAsync(repo, User(shadow), FileManagementRtId)).Should().BeFalse("cross-tenant shadow user (AB#5708)");
            (await HasRoleAsync(repo, Group(owners), FileManagementRtId)).Should().BeFalse("never granted on a group");
            (await HasRoleAsync(repo, Client(serviceAccount), FileManagementRtId)).Should().BeFalse("clients are not human administrators");
            (await GetMappedRoleIdsAsync(repo, mapping)).Should().BeEquivalentTo(
                [AdminPanelRtId.ToString(), TenantManagementRtId.ToString()], "mappings are untouched");
            (await HasRoleAsync(repo, User(direct), AdminPanelRtId)).Should().BeTrue("nothing is removed");
            (await CountEdgesAsync(repo, User(alreadyHas), FileManagementRtId)).Should().Be(1, "no second edge for a holder");
        }

        // An operator removes the grant again; the next run must not re-add it (own run-once marker).
        await UnlinkAsync(repo, User(direct), Role(FileManagementRtId), assigned);
        var second = await TenantAdministratorFileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);
        second.Status.Should().Be(TenantAdministratorFileRoleGrantStatus.AlreadyDone);
        (await HasRoleAsync(repo, User(direct), FileManagementRtId)).Should().BeFalse();

        using var session = await tenantContext.GetAdminSessionAsync();
        var marker = await tenantContext.GetConfigurationAsync<TenantAdministratorFileRoleGrantMarker>(
            session, IdentityServiceConstants.TenantAdministratorFileRoleGrantKey, defaultValue: null);
        marker.Should().NotBeNull();
        marker!.Version.Should().Be(2);
        marker.GrantedUserIds.Should().BeEquivalentTo([direct.ToString(), viaGroup.ToString()]);
    }

    [Fact]
    public async Task FileManagementMissing_WritesNothingAndNoMarker_ThenRunsOnceTheRoleExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, AdminPanelRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        var admin = await InsertUserAsync(repo, "admin");
        await LinkAsync(repo, User(admin), Role(AdminPanelRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        var first = await TenantAdministratorFileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);
        first.Status.Should().Be(TenantAdministratorFileRoleGrantStatus.RoleMissing);

        await InsertRoleAsync(repo, FileManagementRtId, IdentityServiceConstants.FileManagementRole);
        var second = await TenantAdministratorFileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        second.Status.Should().Be(TenantAdministratorFileRoleGrantStatus.Completed, "no marker may be recorded while the role is missing");
        second.GrantedUserIds.Should().Equal(admin.ToString());
        (await HasRoleAsync(repo, User(admin), FileManagementRtId)).Should().BeTrue();
    }

    [Fact]
    public async Task TenantSetup_RunsTheAdministratorGrant_AfterTheRolesExist()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertAllRolesAsync(repo);
        var admin = await InsertUserAsync(repo, "admin");
        await LinkAsync(repo, User(admin), Role(AdminPanelRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(admin), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        // The production trigger: identity startup / PosUpdateTenant run SetupAsync for every tenant.
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);

        (await HasRoleAsync(repo, User(admin), FileManagementRtId)).Should().BeTrue();
    }

    // ---------- helpers ----------

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"tagrant-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        // Imports the Identity CK model; without the blueprint catalog the File roles do not exist yet, so the
        // grant step inside the setup ends as RoleMissing and records no marker.
        await setup.SetupAsync(tenantId);

        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        var repo = tenantContext.GetTenantRepositoryAsAdmin();

        using var check = await repo.GetSessionAsync();
        check.StartTransaction();
        var roles = await repo.GetRtEntitiesByTypeAsync<RtRole>(check, RtEntityQueryOptions.Create());
        await check.CommitTransactionAsync();
        roles.Items.Should().NotContain(r => r.Name == IdentityServiceConstants.FileViewerRole,
            "precondition: the fixture seeds no blueprint roles; if it starts to, the marker is already set and " +
            "these tests must arrange differently");

        return (tenantContext, repo);
    }

    private static async Task InsertAllRolesAsync(ITenantRepository repo)
    {
        await InsertRoleAsync(repo, ReportingManagementRtId, CommonConstants.ReportingManagementRole);
        await InsertRoleAsync(repo, ReportingViewerRtId, CommonConstants.ReportingViewerRole);
        await InsertRoleAsync(repo, FileManagementRtId, IdentityServiceConstants.FileManagementRole);
        await InsertRoleAsync(repo, FileViewerRtId, IdentityServiceConstants.FileViewerRole);
        await InsertRoleAsync(repo, AdminPanelRtId, CommonConstants.AdminPanelManagementRole);
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, DevelopmentRtId, CommonConstants.DevelopmentRole);
    }

    private static RtEntityId User(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtUser>(), id);
    private static RtEntityId Group(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), id);
    private static RtEntityId Client(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtClient>(), id);
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

    private static async Task<OctoObjectId> InsertGroupAsync(ITenantRepository repo, string prefix)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var name = $"{prefix}-{Guid.NewGuid():N}";
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtGroup
        {
            RtId = rtId, GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> InsertClientAsync(ITenantRepository repo, string prefix)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = true,
            ClientId = $"{prefix}-{Guid.NewGuid():N}",
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
            AllowedScopes = new AttributeStringValueList { "octo_api" }
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<OctoObjectId> InsertMappingAsync(ITenantRepository repo, IEnumerable<string> mappedRoleIds)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
        {
            RtId = rtId,
            SourceTenantId = "home",
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = $"user-{Guid.NewGuid():N}",
            MappedRoleIds = new AttributeStringValueList(mappedRoleIds.ToList())
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<IReadOnlyList<string>> GetMappedRoleIdsAsync(ITenantRepository repo, OctoObjectId mappingRtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var mapping = await repo.GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mappingRtId);
        await session.CommitTransactionAsync();
        return mapping!.MappedRoleIds?.ToList() ?? [];
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

    private static async Task<OctoObjectId> InsertShadowUserAsync(ITenantRepository repo)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var userName = $"xt_home_{Guid.NewGuid():N}";
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

    private static async Task<int> CountEdgesAsync(ITenantRepository repo, RtEntityId origin, OctoObjectId roleRtId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var edges = await repo.GetRtAssociationsAsync(session, origin,
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        await session.CommitTransactionAsync();
        return edges.Items.Count(e => e.TargetRtId == roleRtId);
    }
}
