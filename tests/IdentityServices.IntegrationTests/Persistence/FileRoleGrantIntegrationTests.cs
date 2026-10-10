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
///     AB#6180: the one-time grant of FileManagement / FileViewer to the holders of ReportingManagement /
///     ReportingViewer, against a real MongoDB (Testcontainers) — reads the role holdings through the production
///     read path, writes AssignedRole edges and MappedRoleIds appends, records the run-once marker, never removes
///     anything. Each test uses its own child tenant. The fixture does not register the System.Identity.Bootstrap
///     blueprint catalog (Program.cs-only), so the roles are materialised in-test at their blueprint rtIds.
/// </summary>
[Collection("Sequential")]
public class FileRoleGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId ReportingManagementRtId = new("660000000000000000000009");
    private static readonly OctoObjectId ReportingViewerRtId = new("66000000000000000000000A");
    private static readonly OctoObjectId FileManagementRtId = new("660000000000000000000061");
    private static readonly OctoObjectId FileViewerRtId = new("660000000000000000000062");
    private static readonly OctoObjectId DevelopmentRtId = new("660000000000000000000004");

    private readonly IdentityServicesFixture _fixture;

    public FileRoleGrantIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ReportingRoleHolders_GetTheFileRolesOnce_AdditiveOnly()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertAllRolesAsync(repo);

        var viewer = await InsertUserAsync(repo, "viewer");
        var manager = await InsertUserAsync(repo, "manager");
        var developer = await InsertUserAsync(repo, "developer");
        var groupMember = await InsertUserAsync(repo, "member");
        var viewersGroup = await InsertGroupAsync(repo, "viewers");
        var serviceAccount = await InsertClientAsync(repo, "svc");
        var mapping = await InsertMappingAsync(repo, [ReportingViewerRtId.ToString(), DevelopmentRtId.ToString()]);

        await LinkAsync(repo, User(viewer), Role(ReportingViewerRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(manager), Role(ReportingManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, User(developer), Role(DevelopmentRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(viewersGroup), Role(ReportingViewerRtId), IdentityAssociationConstants.AssignedRoleId);
        await LinkAsync(repo, Group(viewersGroup), User(groupMember), IdentityAssociationConstants.GroupMemberId);
        await LinkAsync(repo, Client(serviceAccount), Role(ReportingManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        var result = await FileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        result.Status.Should().Be(FileRoleGrantStatus.Completed);
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await HasRoleAsync(repo, User(viewer), FileViewerRtId)).Should().BeTrue("ReportingViewer held directly");
            (await HasRoleAsync(repo, User(viewer), FileManagementRtId)).Should().BeFalse();
            (await HasRoleAsync(repo, User(manager), FileManagementRtId)).Should().BeTrue("ReportingManagement held directly");
            (await HasRoleAsync(repo, User(manager), FileViewerRtId)).Should().BeFalse(
                "ReportingManagement maps to FileManagement only, exactly like today's Reporting roles");
            (await HasRoleAsync(repo, User(developer), FileViewerRtId)).Should().BeFalse("no Reporting role");
            (await HasRoleAsync(repo, Group(viewersGroup), FileViewerRtId)).Should().BeTrue("granted on the group itself");
            (await HasRoleAsync(repo, User(groupMember), FileViewerRtId)).Should().BeFalse(
                "the member inherits it through the group, not as a direct edge");
            (await HasRoleAsync(repo, Client(serviceAccount), FileManagementRtId)).Should().BeTrue("clients are holders too");
            (await GetMappedRoleIdsAsync(repo, mapping)).Should().BeEquivalentTo(
                [ReportingViewerRtId.ToString(), DevelopmentRtId.ToString(), FileViewerRtId.ToString()],
                "FileViewer is appended, existing entries stay");
            (await HasRoleAsync(repo, User(viewer), ReportingViewerRtId)).Should().BeTrue("nothing is removed");
            (await HasRoleAsync(repo, Group(viewersGroup), ReportingViewerRtId)).Should().BeTrue("nothing is removed");
        }

        // An operator removes the grant again — the next setup must not re-add it (run-once marker).
        await UnlinkAsync(repo, User(viewer), Role(FileViewerRtId), IdentityAssociationConstants.AssignedRoleId);
        var second = await FileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        second.Status.Should().Be(FileRoleGrantStatus.AlreadyDone);
        (await HasRoleAsync(repo, User(viewer), FileViewerRtId)).Should().BeFalse();
    }

    [Fact]
    public async Task FileRolesMissing_WritesNothingAndNoMarker_ThenRunsOnceTheRolesExist()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, ReportingViewerRtId, CommonConstants.ReportingViewerRole);
        await InsertRoleAsync(repo, ReportingManagementRtId, CommonConstants.ReportingManagementRole);
        var viewer = await InsertUserAsync(repo, "viewer");
        await LinkAsync(repo, User(viewer), Role(ReportingViewerRtId), IdentityAssociationConstants.AssignedRoleId);

        var first = await FileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);
        first.Status.Should().Be(FileRoleGrantStatus.RoleMissing);

        await InsertRoleAsync(repo, FileManagementRtId, IdentityServiceConstants.FileManagementRole);
        await InsertRoleAsync(repo, FileViewerRtId, IdentityServiceConstants.FileViewerRole);
        var second = await FileRoleGrant.EnsureAsync(tenantContext, NullLogger.Instance);

        second.Status.Should().Be(FileRoleGrantStatus.Completed, "no marker may be recorded while a role is missing");
        second.Plan.Edges.Should().Equal(
            new FileRoleGrantEdge(FileRoleGrantSubjectKind.User, viewer.ToString(), FileViewerRtId.ToString()));
        (await HasRoleAsync(repo, User(viewer), FileViewerRtId)).Should().BeTrue();
    }

    [Fact]
    public async Task TenantSetup_RunsTheGrant_AfterTheRolesExist()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertAllRolesAsync(repo);
        var viewer = await InsertUserAsync(repo, "viewer");
        await LinkAsync(repo, User(viewer), Role(ReportingViewerRtId), IdentityAssociationConstants.AssignedRoleId);

        // The production trigger: identity startup / PosUpdateTenant run SetupAsync for every tenant.
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);

        (await HasRoleAsync(repo, User(viewer), FileViewerRtId)).Should().BeTrue();
        using var session = await tenantContext.GetAdminSessionAsync();
        var marker = await tenantContext.GetConfigurationAsync<FileRoleGrantMarker>(
            session, IdentityServiceConstants.FileRoleGrantKey, defaultValue: null);
        marker.Should().NotBeNull();
        marker!.GrantedAssignments.Should().Equal($"User:{viewer}:{IdentityServiceConstants.FileViewerRole}");
    }

    // ---------- helpers ----------

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"frgrant-{Guid.NewGuid():N}"[..24];
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
}
