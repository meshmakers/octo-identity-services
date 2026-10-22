using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.ScratchTenants;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#7192: the creator of a scratch tenant (a client-credentials client of its parent, created with the opt-in
///     flag) becomes administrator of it - its mirror joins <c>TenantOwners</c> of the child. Against a real MongoDB
///     (Testcontainers) with the production tenant setup: the grant is given from the marker in the system tenant, only
///     to that exact client, survives a repeated setup (an identity restart) and a re-provisioned mirror, and a revoke
///     is persisted so the setup does not grant it again. The fixture seeds no blueprint, so the TenantOwners group is
///     materialised in-test.
/// </summary>
[Collection("Sequential")]
public class ScratchTenantCreatorGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ScratchTenantCreatorGrantIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task MarkedTenant_Setup_GrantsOnlyTheCreatorsMirror_TenantOwners()
    {
        var systemContext = await InitializeAsync();
        var creator = NewClientId("creator");
        var bystander = NewClientId("bystander");
        await CreateFlaggedClientAsync(systemContext, creator);
        await CreateFlaggedClientAsync(systemContext, bystander);

        var childId = await CreateScratchChildAsync(systemContext, creator);

        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeTrue(
            "the creator's mirror is administrator of the tenant it created");
        (await IsTenantOwnersMemberAsync(systemContext, childId, bystander)).Should().BeFalse(
            "another client flagged for mirroring gets nothing");
        var marker = await GetMarkerAsync(systemContext, childId);
        marker!.GrantedAtUtc.Should().NotBeNull();
        marker.RevokedAtUtc.Should().BeNull();
    }

    [Fact]
    public async Task UnmarkedTenant_Setup_GrantsNobody()
    {
        var systemContext = await InitializeAsync();
        var client = NewClientId("plain");
        await CreateFlaggedClientAsync(systemContext, client);

        var childId = await CreateChildAsync(systemContext, marker: null);

        (await IsTenantOwnersMemberAsync(systemContext, childId, client)).Should().BeFalse(
            "without the scratch flag the behaviour is unchanged: a mirror gets no roles in the child");
        (await GetMarkerAsync(systemContext, childId)).Should().BeNull();
    }

    [Fact]
    public async Task Grant_SurvivesARepeatedSetup_AndAReProvisionedMirror()
    {
        var systemContext = await InitializeAsync();
        var creator = NewClientId("survivor");
        await CreateFlaggedClientAsync(systemContext, creator);
        var childId = await CreateScratchChildAsync(systemContext, creator);
        var mirrorService = _fixture.GetService<IClientMirrorProvisioningService>();
        var firstMirror = await FindChildClientAsync(systemContext, childId, creator);

        // An identity restart runs the tenant setup of every tenant again.
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(childId);
        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeTrue("after a restart");

        // A re-provisioned mirror is a new record: the edges of the old one are gone with it.
        await mirrorService.RemoveMirrorAsync(systemContext.TenantId, creator, childId);
        (await FindChildClientAsync(systemContext, childId, creator)).Should().BeNull("precondition: mirror removed");
        await mirrorService.ProvisionInTenantAsync(systemContext.TenantId, creator, childId);

        var secondMirror = await FindChildClientAsync(systemContext, childId, creator);
        secondMirror!.RtId.Should().NotBe(firstMirror!.RtId, "precondition: a new record");
        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeTrue(
            "the mirror provisioning re-applies the creator grant");
    }

    [Fact]
    public async Task Revoke_IsPersisted_AndTheSetupDoesNotGrantAgain()
    {
        var systemContext = await InitializeAsync();
        var creator = NewClientId("revoked");
        await CreateFlaggedClientAsync(systemContext, creator);
        var childId = await CreateScratchChildAsync(systemContext, creator);
        var service = _fixture.GetService<IScratchTenantGrantService>();

        var mirror = await FindChildClientAsync(systemContext, childId, creator);
        var group = await FindTenantOwnersAsync(systemContext, childId);
        await RemoveMembershipAsync(systemContext, childId, group, mirror!);

        var revoked = await service.RecordRevocationAsync(childId, group.RtId, mirror!.RtId, "tenant-admin");

        revoked.Should().BeTrue();
        var marker = await GetMarkerAsync(systemContext, childId);
        marker!.RevokedAtUtc.Should().NotBeNull();
        marker.RevokedBy.Should().Be("tenant-admin");

        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(childId);
        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeFalse(
            "a revoked grant stays revoked across a setup");
        (await service.EnsureGrantAsync(childId)).Should().Be(ScratchGrantStatus.Revoked);
    }

    [Fact]
    public async Task RevokeRecordedWhileTheGrantIsApplied_RemovesTheMembershipAgain()
    {
        var systemContext = await InitializeAsync();
        var creator = NewClientId("racing");
        await CreateFlaggedClientAsync(systemContext, creator);
        var service = new RevokingDuringGrantService(systemContext);

        var childId = await CreateChildAsync(systemContext, new ScratchTenantMarker
        {
            ParentTenantId = systemContext.TenantId, CreatorClientId = creator, CreatedAtUtc = DateTime.UtcNow
        }, runGrant: false);

        (await service.EnsureGrantAsync(childId)).Should().Be(ScratchGrantStatus.Revoked);
        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeFalse(
            "a revoke that another replica recorded after the read of the marker must not leave the creator in the group");
        (await GetMarkerAsync(systemContext, childId))!.GrantedAtUtc.Should().BeNull();
    }

    /// <summary>Records the revoke the way another replica would, between the insert of the membership and the re-check.</summary>
    private sealed class RevokingDuringGrantService : ScratchTenantGrantService
    {
        private readonly ISystemContext _context;

        public RevokingDuringGrantService(ISystemContext context)
            : base(NullLogger<ScratchTenantGrantService>.Instance, context)
        {
            _context = context;
        }

        protected override async Task OnMembershipInsertedAsync(string childTenantId)
        {
            using var session = await _context.GetAdminSessionAsync();
            var key = ScratchTenantMarker.GetConfigurationKey(childTenantId);
            var marker = await _context.GetConfigurationAsync<ScratchTenantMarker>(session, key, defaultValue: null);
            marker!.RevokedAtUtc = DateTime.UtcNow;
            marker.RevokedBy = "other-replica";
            await _context.SetConfigurationAsync(session, key, marker);
        }
    }

    [Fact]
    public async Task Removal_OfAnotherClient_IsNoRevoke()
    {
        var systemContext = await InitializeAsync();
        var creator = NewClientId("kept");
        var other = NewClientId("other");
        await CreateFlaggedClientAsync(systemContext, creator);
        await CreateFlaggedClientAsync(systemContext, other);
        var childId = await CreateScratchChildAsync(systemContext, creator);
        var service = _fixture.GetService<IScratchTenantGrantService>();
        var otherMirror = await FindChildClientAsync(systemContext, childId, other);
        var group = await FindTenantOwnersAsync(systemContext, childId);

        var revoked = await service.RecordRevocationAsync(childId, group.RtId, otherMirror!.RtId, "tenant-admin");

        revoked.Should().BeFalse();
        (await GetMarkerAsync(systemContext, childId))!.RevokedAtUtc.Should().BeNull();
        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeTrue();
    }

    [Fact]
    public async Task ClientOfTheSameIdThatIsNoMirror_IsNeverGranted()
    {
        var systemContext = await InitializeAsync();
        // No client of this id is flagged in the parent, so the only client of that id in the child is a local one
        // (or one that came with a restored dump).
        var creator = NewClientId("impostor");
        var childId = await CreateChildAsync(systemContext, new ScratchTenantMarker
        {
            ParentTenantId = systemContext.TenantId, CreatorClientId = creator, CreatedAtUtc = DateTime.UtcNow
        }, beforeSetup: async repo => await InsertLocalClientAsync(repo, creator));

        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeFalse();
        (await _fixture.GetService<IScratchTenantGrantService>().EnsureGrantAsync(childId))
            .Should().Be(ScratchGrantStatus.MirrorMissing);
    }

    [Fact]
    public async Task MarkerOfAForeignParent_IsNotHonoured()
    {
        var systemContext = await InitializeAsync();
        var creator = NewClientId("foreign");
        await CreateFlaggedClientAsync(systemContext, creator);

        var childId = await CreateChildAsync(systemContext, new ScratchTenantMarker
        {
            ParentTenantId = "someotherparent", CreatorClientId = creator, CreatedAtUtc = DateTime.UtcNow
        });

        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeFalse(
            "the marker names a tenant that is not the child's parent");
        (await _fixture.GetService<IScratchTenantGrantService>().EnsureGrantAsync(childId))
            .Should().Be(ScratchGrantStatus.ParentMismatch);
    }

    [Fact]
    public async Task NonSystemParent_TheMirrorIsProvisionedFirst_ThenGranted()
    {
        var systemContext = await InitializeAsync();
        var parentId = await CreateChildAsync(systemContext, marker: null);
        var creator = NewClientId("nested");
        var parentContext = await systemContext.GetChildTenantContextAsync(parentId);
        await CreateFlaggedClientAsync(parentContext.GetTenantRepositoryAsAdmin(), creator);

        var childId = await CreateGrandchildAsync(systemContext, parentId, new ScratchTenantMarker
        {
            ParentTenantId = parentId, CreatorClientId = creator, CreatedAtUtc = DateTime.UtcNow
        });

        var mirror = await FindChildClientAsync(systemContext, childId, creator);
        mirror.Should().NotBeNull("the setup provisions the mirror of a non-system parent for a scratch tenant");
        mirror!.ProvisionedByParentTenantId.Should().Be(parentId);
        (await IsTenantOwnersMemberAsync(systemContext, childId, creator)).Should().BeTrue();
    }

    [Fact]
    public async Task GrantAndRevoke_AreAudited_WithoutSecrets()
    {
        var systemContext = await InitializeAsync();
        var creator = NewClientId("audited");
        await CreateFlaggedClientAsync(systemContext, creator, secretHash: "very-secret-hash-value");
        var events = Substitute.For<IEventRepository>();
        var service = new ScratchTenantGrantService(NullLogger<ScratchTenantGrantService>.Instance, systemContext,
            events);

        var childId = await CreateChildAsync(systemContext, new ScratchTenantMarker
        {
            ParentTenantId = systemContext.TenantId, CreatorClientId = creator, CreatedAtUtc = DateTime.UtcNow
        }, runGrant: false);
        (await service.EnsureGrantAsync(childId)).Should().Be(ScratchGrantStatus.Granted);

        var mirror = await FindChildClientAsync(systemContext, childId, creator);
        var group = await FindTenantOwnersAsync(systemContext, childId);
        await RemoveMembershipAsync(systemContext, childId, group, mirror!);
        await service.RecordRevocationAsync(childId, group.RtId, mirror!.RtId, "tenant-admin");

        var messages = events.ReceivedCalls()
            .Where(c => c.GetMethodInfo().Name is nameof(IEventRepository.StoreInformationEvent)
                or nameof(IEventRepository.StoreSystemInformationEvent))
            .Select(c => c.GetArguments().OfType<string>().Last())
            .ToList();
        messages.Should().Contain(m => m.Contains("access granted") && m.Contains(creator));
        messages.Should().Contain(m => m.Contains("access revoked") && m.Contains("tenant-admin"));
        messages.Should().OnlyContain(m => !m.Contains("very-secret-hash-value"));
        await events.Received().StoreInformationEvent(childId, RtEventSourcesEnum.IdentityService,
            Arg.Is<string>(m => m.Contains("access granted")));
    }

    // ---------- helpers ----------

    private async Task<ISystemContext> InitializeAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(systemContext.TenantId);
        return systemContext;
    }

    private static string NewClientId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private Task<string> CreateScratchChildAsync(ISystemContext systemContext, string creatorClientId) =>
        CreateChildAsync(systemContext, new ScratchTenantMarker
        {
            ParentTenantId = systemContext.TenantId, CreatorClientId = creatorClientId, CreatedAtUtc = DateTime.UtcNow
        });

    /// <summary>
    ///     Creates a child like the asset repository does: the marker is written BEFORE the tenant exists, then the tenant
    ///     is created and set up. The fixture seeds no blueprint, so the TenantOwners group is materialised after the
    ///     first setup and the setup runs once more (the production blueprint apply creates the group before the grant).
    /// </summary>
    private async Task<string> CreateChildAsync(ISystemContext systemContext, ScratchTenantMarker? marker,
        Func<ITenantRepository, Task>? beforeSetup = null, bool runGrant = true)
    {
        var tenantId = $"scr7192-{Guid.NewGuid():N}"[..24];
        if (marker != null)
        {
            using var markerSession = await systemContext.GetAdminSessionAsync();
            await systemContext.SetConfigurationAsync(markerSession, ScratchTenantMarker.GetConfigurationKey(tenantId),
                marker);
        }

        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await SetupAndSeedAsync(systemContext, tenantId, beforeSetup, runGrant);
        return tenantId;
    }

    private async Task<string> CreateGrandchildAsync(ISystemContext systemContext, string parentId,
        ScratchTenantMarker marker)
    {
        var tenantId = $"scr7192-{Guid.NewGuid():N}"[..24];
        using (var markerSession = await systemContext.GetAdminSessionAsync())
        {
            await systemContext.SetConfigurationAsync(markerSession, ScratchTenantMarker.GetConfigurationKey(tenantId),
                marker);
        }

        var parentContext = await systemContext.GetChildTenantContextAsync(parentId);
        using (var session = await parentContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await parentContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await SetupAndSeedAsync(systemContext, tenantId, null, runGrant: true);
        return tenantId;
    }

    private async Task SetupAndSeedAsync(ISystemContext systemContext, string tenantId,
        Func<ITenantRepository, Task>? beforeSetup, bool runGrant)
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        // First pass imports the identity CK model into the child (and finds no group yet).
        await setup.SetupAsync(tenantId);

        var repo = (await systemContext.GetChildTenantContextAsync(tenantId)).GetTenantRepositoryAsAdmin();
        await InsertTenantOwnersGroupAsync(repo);
        if (beforeSetup != null)
        {
            await beforeSetup(repo);
        }

        if (runGrant)
        {
            await setup.SetupAsync(tenantId);
        }
    }

    private static async Task InsertTenantOwnersGroupAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var existing = await repo.GetRtEntitiesByTypeAsync<RtGroup>(session, RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName), "TENANTOWNERS"));
        if (!existing.Items.Any())
        {
            await repo.InsertOneRtEntityAsync(session, new RtGroup
            {
                RtId = new OctoObjectId("660000000000000000000040"),
                GroupName = CommonConstants.TenantOwnersGroup,
                NormalizedGroupName = "TENANTOWNERS"
            });
        }

        await session.CommitTransactionAsync();
    }

    private static async Task InsertLocalClientAsync(ITenantRepository repo, string clientId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = OctoObjectId.GenerateNewId(),
            Enabled = true,
            ClientId = clientId,
            ProtocolType = "oidc",
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
            ClientSecrets = new AttributeRecordValueList<RtSecretRecord>()
        });
        await session.CommitTransactionAsync();
    }

    private static Task CreateFlaggedClientAsync(ISystemContext systemContext, string clientId,
        string secretHash = "test-hash") =>
        CreateFlaggedClientAsync(systemContext.GetSystemTenantRepositoryAsAdmin(), clientId, secretHash);

    private static async Task CreateFlaggedClientAsync(ITenantRepository parentRepo, string clientId,
        string secretHash = "test-hash")
    {
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        await parentRepo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = OctoObjectId.GenerateNewId(),
            Enabled = true,
            ClientId = clientId,
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
            AllowedScopes = new AttributeStringValueList { "octo_api" },
            ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
            {
                new() { Value = secretHash, Type = "SharedSecret" }
            },
            AutoProvisionInChildTenants = true
        });
        await session.CommitTransactionAsync();
    }

    private static async Task<ScratchTenantMarker?> GetMarkerAsync(ISystemContext systemContext, string tenantId)
    {
        using var session = await systemContext.GetAdminSessionAsync();
        return await systemContext.GetConfigurationAsync<ScratchTenantMarker>(session,
            ScratchTenantMarker.GetConfigurationKey(tenantId), defaultValue: null);
    }

    private static async Task<RtClient?> FindChildClientAsync(ISystemContext systemContext, string tenantId,
        string clientId)
    {
        var repo = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        using var session = await repo!.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private static async Task<RtGroup> FindTenantOwnersAsync(ISystemContext systemContext, string tenantId)
    {
        var repo = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        using var session = await repo!.GetSessionAsync();
        var groups = await repo.GetRtEntitiesByTypeAsync<RtGroup>(session, RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName), "TENANTOWNERS"));
        return groups.Items.Single();
    }

    private static async Task<bool> IsTenantOwnersMemberAsync(ISystemContext systemContext, string tenantId,
        string clientId)
    {
        var client = await FindChildClientAsync(systemContext, tenantId, clientId);
        if (client == null)
        {
            return false;
        }

        var group = await FindTenantOwnersAsync(systemContext, tenantId);
        var repo = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        using var session = await repo!.GetSessionAsync();
        var edge = await repo.GetRtAssociationOrDefaultAsync(session, group.ToRtEntityId(), client.ToRtEntityId(),
            IdentityAssociationConstants.GroupMemberId);
        return edge != null;
    }

    private static async Task RemoveMembershipAsync(ISystemContext systemContext, string tenantId, RtGroup group,
        RtClient client)
    {
        var repo = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        using var session = await repo!.GetSessionAsync();
        session.StartTransaction();
        await repo.ApplyChangesAsync(session,
            [AssociationUpdateInfo.CreateDelete(group.ToRtEntityId(), client.ToRtEntityId(),
                IdentityAssociationConstants.GroupMemberId)], new OperationResult());
        await session.CommitTransactionAsync();
    }
}
