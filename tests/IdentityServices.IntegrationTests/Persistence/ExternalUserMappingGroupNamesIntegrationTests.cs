using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// Regression for the bug where <c>GetExternalTenantUserMappings</c> (per-tenant controller / octo-cli)
/// always returned empty <c>GroupNames</c> even when the mapping was a group member: the
/// per-tenant controller never resolved the inbound GroupMember association. Pins that
/// <see cref="IGroupStore.GetGroupNamesForExternalUserMappingAsync"/> resolves the group(s) a
/// cross-tenant mapping belongs to (roles are inherited via the group, so this is the only signal
/// that a group-based grant took effect).
/// </summary>
[Collection("Sequential")]
public class ExternalUserMappingGroupNamesIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ExternalUserMappingGroupNamesIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task GetGroupNamesForExternalUserMapping_MemberOfGroup_ReturnsGroupName()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (groupStore, repo) = CreateStores();

        var mappingRtId = await CreateMappingAsync(repo, "member@example.io");
        var groupName = NewId("SuperUser");
        var groupRtId = await CreateGroupAsync(repo, groupName);

        await groupStore.AddMemberExternalUserAsync(groupRtId, mappingRtId.ToString());

        var groupNames = await groupStore.GetGroupNamesForExternalUserMappingAsync(mappingRtId);

        groupNames.Should().ContainSingle().Which.Should().Be(groupName);
        (await groupStore.GetMemberExternalUserIdsAsync(groupRtId))
            .Should().Contain(mappingRtId.ToString());
    }

    [Fact]
    public async Task GetGroupNamesForExternalUserMapping_NotAMember_ReturnsEmpty()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (groupStore, repo) = CreateStores();

        var mappingRtId = await CreateMappingAsync(repo, "lonely@example.io");

        (await groupStore.GetGroupNamesForExternalUserMappingAsync(mappingRtId)).Should().BeEmpty();
    }

    // ---------- helpers ----------

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private (GroupStore groupStore, ITenantRepository repo) CreateStores()
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        var resolver = new FixedTenantResolver(repo);
        return (new GroupStore(resolver), repo);
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

    private static async Task<OctoObjectId> CreateMappingAsync(ITenantRepository repo, string sourceUserName)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
        {
            RtId = rtId,
            SourceTenantId = "octosystem",
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = sourceUserName
        });
        await session.CommitTransactionAsync();
        return rtId;
    }
}
