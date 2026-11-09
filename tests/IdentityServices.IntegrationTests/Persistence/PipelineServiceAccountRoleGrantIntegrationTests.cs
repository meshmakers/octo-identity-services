using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.PipelineServiceAccounts;
using IdentityServices.IntegrationTests.Fixtures;
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
///     AB#6467 / AB#6457 / AB#8581: the recurring grant of the baseline roles (FileManagement, StreamDataReader) to the
///     pipeline service accounts (<c>octo-pipeline-sa-*</c>) against a real MongoDB. Each test uses its own child
///     tenant. The fixture does not apply the System.Identity.Bootstrap blueprint, so the roles are created in-test at
///     their blueprint rtIds.
/// </summary>
[Collection("Sequential")]
public class PipelineServiceAccountRoleGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId FileManagementRtId = new("660000000000000000000061");
    private static readonly OctoObjectId StreamDataReaderRtId = new("66000000000000000000000E");
    private static readonly OctoObjectId CommunicationManagementRtId = new("660000000000000000000003");

    private readonly IdentityServicesFixture _fixture;

    public PipelineServiceAccountRoleGrantIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ExistingAccount_GetsBothRolesOnce_RepeatedRunsWriteNothing_OtherClientsAreUntouched()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertBaselineRolesAsync(repo);
        var pipelineAccount = await InsertClientAsync(repo, "octo-pipeline-sa-");
        var customerClient = await InsertClientAsync(repo, "customer-integration-");
        var alreadyCovered = await InsertClientAsync(repo, "octo-pipeline-sa-");
        await LinkAsync(repo, alreadyCovered, FileManagementRtId);
        await LinkAsync(repo, alreadyCovered, StreamDataReaderRtId);

        var first = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        first.MissingRoles.Should().BeEmpty();
        first.NotApplicableRoles.Should().BeEmpty();
        first.Granted.Select(g => g.RoleName).Should().BeEquivalentTo(
            [IdentityServiceConstants.FileManagementRole, IdentityServiceConstants.StreamDataReaderRole]);
        (await RoleIdsAsync(repo, pipelineAccount)).Should().BeEquivalentTo([FileManagementRtId, StreamDataReaderRtId]);
        (await RoleIdsAsync(repo, alreadyCovered)).Should().BeEquivalentTo([FileManagementRtId, StreamDataReaderRtId]);
        (await RoleIdsAsync(repo, customerClient)).Should().BeEmpty("only the controller's accounts are covered");

        var second = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
        second.Granted.Should().BeEmpty("the second run finds every account covered");
        (await RoleIdsAsync(repo, pipelineAccount)).Should().HaveCount(2, "no duplicate edge");
    }

    [Fact]
    public async Task LegacyAccountWithOtherRoles_GetsStreamDataReader_AndKeepsEveryRoleItHad()
    {
        // AB#8581 AC1: a legacy account (created before CK 3.32.0, no AssignedRoleNames) the controller cannot touch.
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertBaselineRolesAsync(repo);
        await InsertRoleAsync(repo, CommunicationManagementRtId, "CommunicationManagement");
        var customRoleId = OctoObjectId.GenerateNewId();
        await InsertRoleAsync(repo, customRoleId, "LegacyCustomRole");
        var legacy = await InsertClientAsync(repo, "octo-pipeline-sa-");
        await LinkAsync(repo, legacy, CommunicationManagementRtId);
        await LinkAsync(repo, legacy, customRoleId);
        await LinkAsync(repo, legacy, FileManagementRtId);

        var result = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        result.Granted.Select(g => g.RoleName).Should().Equal(IdentityServiceConstants.StreamDataReaderRole);
        (await RoleIdsAsync(repo, legacy)).Should().BeEquivalentTo(
            [CommunicationManagementRtId, customRoleId, FileManagementRtId, StreamDataReaderRtId],
            "the grant is additive: every role the account had stays");
    }

    [Fact]
    public async Task AccountCreatedLater_IsPickedUpByTheNextRun()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertBaselineRolesAsync(repo);
        await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        var late = await InsertClientAsync(repo, "octo-pipeline-sa-");
        (await PipelineServiceAccountRoleGrant.FindMissingRolesAsync(tenantContext, () => true, NullLogger.Instance))
            .Select(m => m.RoleName).Should().BeEquivalentTo(
                [IdentityServiceConstants.FileManagementRole, IdentityServiceConstants.StreamDataReaderRole],
                "the detection names both missing roles of the uncovered account");

        var run = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        run.Granted.Should().HaveCount(2);
        (await RoleIdsAsync(repo, late)).Should().BeEquivalentTo([FileManagementRtId, StreamDataReaderRtId]);
        (await PipelineServiceAccountRoleGrant.FindMissingRolesAsync(tenantContext, () => true, NullLogger.Instance))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task TenantWithoutSystemFiles_GetsStreamDataReaderOnly()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertBaselineRolesAsync(repo);
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");

        var result = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => false, NullLogger.Instance);

        result.NotApplicableRoles.Should().Equal(IdentityServiceConstants.FileManagementRole);
        (await RoleIdsAsync(repo, account)).Should().Equal([StreamDataReaderRtId],
            "FileManagement needs System.Files; StreamDataReader does not");
        (await PipelineServiceAccountRoleGrant.FindMissingRolesAsync(tenantContext, () => false, NullLogger.Instance))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task RolesMissing_WriteNothing_AndTheNextRunGrantsEachRoleOnceItExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");

        var first = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
        first.MissingRoles.Should().BeEquivalentTo(
            [IdentityServiceConstants.FileManagementRole, IdentityServiceConstants.StreamDataReaderRole]);
        first.Granted.Should().BeEmpty();

        await InsertRoleAsync(repo, StreamDataReaderRtId, IdentityServiceConstants.StreamDataReaderRole);
        var second = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
        second.MissingRoles.Should().Equal(IdentityServiceConstants.FileManagementRole);
        (await RoleIdsAsync(repo, account)).Should().Equal([StreamDataReaderRtId], "only seeded roles are granted");

        await InsertRoleAsync(repo, FileManagementRtId, IdentityServiceConstants.FileManagementRole);
        var third = await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
        third.Granted.Select(g => g.RoleName).Should().Equal(IdentityServiceConstants.FileManagementRole);
    }

    [Fact]
    public async Task TenantSetup_GrantsStreamDataReader_ButNotFileManagementWithoutSystemFilesInTheCkCache()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertBaselineRolesAsync(repo);
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");

        // The production trigger. The fixture tenant has no System.Files model, so the wired probe skips FileManagement.
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);

        (await RoleIdsAsync(repo, account)).Should().Equal([StreamDataReaderRtId],
            "no System.Files in this tenant's CK cache; StreamDataReader is granted regardless");
    }

    [Fact]
    public async Task ConcurrentGrants_NeverLeaveADuplicateEdge()
    {
        // The setup pass and the identity-data consumer can reach the same account at the same moment.
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertBaselineRolesAsync(repo);
        var accounts = new List<OctoObjectId>();
        for (var i = 0; i < 6; i++)
        {
            accounts.Add(await InsertClientAsync(repo, "octo-pipeline-sa-"));
        }

        var runs = Enumerable.Range(0, 6).Select(_ => Task.Run(async () =>
        {
            try
            {
                await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
            }
            catch (Exception)
            {
                // a lost race may surface as a write conflict; the next run must still converge
            }
        })).ToArray();
        await Task.WhenAll(runs);
        await PipelineServiceAccountRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        foreach (var account in accounts)
        {
            (await RoleIdsAsync(repo, account)).Should().HaveCount(2,
                "exactly one edge per account and role after concurrent runs");
        }
    }

    // ---------- helpers ----------

    private async Task<(ITenantContext TenantContext, ITenantRepository Repo)> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"pipesa-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await setup.SetupAsync(tenantId);
        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        return (tenantContext, tenantContext.GetTenantRepositoryAsAdmin());
    }

    private static RtEntityId Client(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtClient>(), id);
    private static RtEntityId Role(OctoObjectId id) => new(RtEntityExtensions.GetRtCkTypeId<RtRole>(), id);

    private static async Task InsertBaselineRolesAsync(ITenantRepository repo)
    {
        await InsertRoleAsync(repo, FileManagementRtId, IdentityServiceConstants.FileManagementRole);
        await InsertRoleAsync(repo, StreamDataReaderRtId, IdentityServiceConstants.StreamDataReaderRole);
    }

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

    private static async Task<OctoObjectId> InsertClientAsync(ITenantRepository repo, string prefix)
    {
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = rtId,
            Enabled = true,
            ClientId = $"{prefix}{Guid.NewGuid():N}",
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
            AllowedScopes = new AttributeStringValueList { "octo_api" }
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task LinkAsync(ITenantRepository repo, OctoObjectId client, OctoObjectId role)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.ApplyChangesAsync(session,
            new[]
            {
                AssociationUpdateInfo.CreateInsert(Client(client), Role(role), IdentityAssociationConstants.AssignedRoleId)
            }, new OperationResult());
        await session.CommitTransactionAsync();
    }

    /// <summary>The role rtIds of every outbound AssignedRole edge, duplicates included.</summary>
    private static async Task<IReadOnlyList<OctoObjectId>> RoleIdsAsync(ITenantRepository repo, OctoObjectId client)
    {
        using var session = await repo.GetSessionAsync();
        var edges = await repo.GetRtAssociationsAsync(session, Client(client),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        return edges.Items.Select(e => e.TargetRtId).ToList();
    }
}
