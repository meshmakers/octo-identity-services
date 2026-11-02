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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#8161: SecretManagement for the TenantOwners group and for octosystem mappings carrying TenantManagement,
///     against a real MongoDB (Testcontainers). Each test uses its own child tenant; the fixture registers no
///     blueprint catalog, so roles and the TenantOwners group are materialised in-test at their blueprint rtIds.
/// </summary>
[Collection("Sequential")]
public class TenantOwnersSecretManagementGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId TenantManagementRtId = new("660000000000000000000001");
    private static readonly OctoObjectId SecretManagementRtId = new("660000000000000000000060");

    private readonly IdentityServicesFixture _fixture;

    public TenantOwnersSecretManagementGrantIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    private string SystemTenantId => _fixture.GetSystemContext().TenantId;

    [Fact]
    public async Task ExistingTenant_TenantOwnersAndOctosystemMappingsGetSecretManagement_NothingElseChanges()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var owners = await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");
        await LinkAsync(repo, Group(owners), Role(TenantManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        var human = await InsertUserAsync(repo, "human");
        var client = await InsertClientAsync(repo);
        var otherGroup = await InsertGroupAsync(repo, OctoObjectId.GenerateNewId(), "others");
        await LinkAsync(repo, Group(owners), Client(client), IdentityAssociationConstants.GroupMemberId);
        var adminMapping = await InsertMappingAsync(repo, SystemTenantId, TenantManagementRtId);
        var ownerMapping = await InsertMappingAsync(repo, SystemTenantId, TenantManagementRtId);
        await LinkAsync(repo, Group(owners), new RtEntityId(
            RtEntityExtensions.GetRtCkTypeId<RtExternalTenantUserMapping>(), ownerMapping),
            IdentityAssociationConstants.GroupMemberId);
        var foreignMapping = await InsertMappingAsync(repo, "meshmakers", TenantManagementRtId);
        var noTmMapping = await InsertMappingAsync(repo, SystemTenantId);

        var result = await TenantOwnersSecretManagementGrant.EnsureAsync(
            tenantContext, SystemTenantId, NullLogger.Instance);

        result.Status.Should().Be(TenantOwnersSecretManagementGrantStatus.Completed);
        result.GroupEdgeAdded.Should().BeTrue();
        result.ExtendedMappingIds.Should().Equal(adminMapping.ToString());
        using (new FluentAssertions.Execution.AssertionScope())
        {
            (await HasSecretManagementAsync(repo, Group(owners))).Should().BeTrue("TenantOwners holds the role");
            (await MappedRolesAsync(repo, adminMapping)).Should().Contain(SecretManagementRtId.ToString())
                .And.Contain(TenantManagementRtId.ToString());
            (await MappedRolesAsync(repo, ownerMapping)).Should().BeEquivalentTo(new[] { TenantManagementRtId.ToString() },
                "a TenantOwners member inherits the role, the list stays as it was");
            (await MappedRolesAsync(repo, foreignMapping)).Should().BeEquivalentTo(new[] { TenantManagementRtId.ToString() },
                "a mapping of another source tenant is not changed");
            (await MappedRolesAsync(repo, noTmMapping)).Should().BeEmpty("no TenantManagement, no grant");
            (await HasSecretManagementAsync(repo, User(human))).Should().BeFalse("no user gains a role");
            (await HasSecretManagementAsync(repo, Client(client))).Should().BeFalse("no direct client edge");
            (await HasSecretManagementAsync(repo, Group(otherGroup))).Should().BeFalse("no other group gains it");
            (await HasRoleAsync(repo, Group(owners), TenantManagementRtId)).Should().BeTrue("nothing is removed");
        }
    }

    [Fact]
    public async Task SecondRun_ChangesNothing_AndAnOperatorRemovalIsNotUndone()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var owners = await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");
        var mapping = await InsertMappingAsync(repo, SystemTenantId, TenantManagementRtId);

        (await TenantOwnersSecretManagementGrant.EnsureAsync(tenantContext, SystemTenantId, NullLogger.Instance))
            .Status.Should().Be(TenantOwnersSecretManagementGrantStatus.Completed);
        (await CountSecretManagementEdgesAsync(repo, Group(owners))).Should().Be(1);

        await UnlinkAsync(repo, Group(owners), Role(SecretManagementRtId), IdentityAssociationConstants.AssignedRoleId);
        var second = await TenantOwnersSecretManagementGrant.EnsureAsync(
            tenantContext, SystemTenantId, NullLogger.Instance);

        second.Status.Should().Be(TenantOwnersSecretManagementGrantStatus.AlreadyDone);
        (await HasSecretManagementAsync(repo, Group(owners))).Should().BeFalse("run-once: an operator choice stays");
        (await MappedRolesAsync(repo, mapping)).Count(r => r == SecretManagementRtId.ToString()).Should().Be(1);
    }

    [Fact]
    public async Task AlreadyHeldRole_IsNotWrittenTwice()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var owners = await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");
        await LinkAsync(repo, Group(owners), Role(SecretManagementRtId), IdentityAssociationConstants.AssignedRoleId);

        var result = await TenantOwnersSecretManagementGrant.EnsureAsync(
            tenantContext, SystemTenantId, NullLogger.Instance);

        result.Status.Should().Be(TenantOwnersSecretManagementGrantStatus.Completed);
        result.GroupEdgeAdded.Should().BeFalse();
        (await CountSecretManagementEdgesAsync(repo, Group(owners))).Should().Be(1);
    }

    [Fact]
    public async Task RoleMissing_WritesNothingAndNoMarker_ThenRunsOnceTheRoleExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        var owners = await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");

        (await TenantOwnersSecretManagementGrant.EnsureAsync(tenantContext, SystemTenantId, NullLogger.Instance))
            .Status.Should().Be(TenantOwnersSecretManagementGrantStatus.RoleMissing);

        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        (await TenantOwnersSecretManagementGrant.EnsureAsync(tenantContext, SystemTenantId, NullLogger.Instance))
            .Status.Should().Be(TenantOwnersSecretManagementGrantStatus.Completed);
        (await HasSecretManagementAsync(repo, Group(owners))).Should().BeTrue();
    }

    [Fact]
    public async Task TenantWithoutTenantOwners_StillExtendsMappings_ButRecordsNoMarker()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var mapping = await InsertMappingAsync(repo, SystemTenantId, TenantManagementRtId);

        var result = await TenantOwnersSecretManagementGrant.EnsureAsync(
            tenantContext, SystemTenantId, NullLogger.Instance);

        result.Status.Should().Be(TenantOwnersSecretManagementGrantStatus.GroupMissing);
        (await MappedRolesAsync(repo, mapping)).Should().Contain(SecretManagementRtId.ToString());
        using var session = await tenantContext.GetAdminSessionAsync();
        (await tenantContext.GetConfigurationAsync<TenantOwnersSecretManagementGrantMarker>(
            session, IdentityServiceConstants.TenantOwnersSecretManagementGrantKey, defaultValue: null))
            .Should().BeNull("the group edge is retried once TenantOwners exists");
    }

    [Fact]
    public async Task TenantSetup_RunsTheGrant()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo, TenantManagementRtId, CommonConstants.TenantManagementRole);
        await InsertRoleAsync(repo, SecretManagementRtId, CommonConstants.SecretManagementRole);
        var owners = await InsertGroupAsync(repo, TenantOwnersRtId, "TenantOwners");

        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);

        (await HasSecretManagementAsync(repo, Group(owners))).Should().BeTrue();
    }

    // ---------- helpers ----------

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"toowngrant-{Guid.NewGuid():N}"[..24];
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
