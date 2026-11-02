using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.FileRoles;
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
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6467 / AB#6457: the recurring grant of FileManagement to the pipeline service accounts
///     (<c>octo-pipeline-sa-*</c>) against a real MongoDB. Each test uses its own child tenant. The fixture does not
///     apply the System.Identity.Bootstrap blueprint, so the role is created in-test at its blueprint rtId.
/// </summary>
[Collection("Sequential")]
public class PipelineServiceAccountFileRoleGrantIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private static readonly OctoObjectId FileManagementRtId = new("660000000000000000000061");

    private readonly IdentityServicesFixture _fixture;

    public PipelineServiceAccountFileRoleGrantIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ExistingAccount_GetsTheRoleOnce_RepeatedRunsWriteNothing_OtherClientsAreUntouched()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo);
        var pipelineAccount = await InsertClientAsync(repo, "octo-pipeline-sa-");
        var customerClient = await InsertClientAsync(repo, "customer-integration-");
        var alreadyCovered = await InsertClientAsync(repo, "octo-pipeline-sa-");
        await LinkAsync(repo, alreadyCovered);

        var first = await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        first.Status.Should().Be(PipelineServiceAccountFileRoleGrantStatus.Completed);
        first.GrantedClientRtIds.Should().Equal(pipelineAccount.ToString());
        (await HasRoleAsync(repo, pipelineAccount)).Should().BeTrue();
        (await HasRoleAsync(repo, alreadyCovered)).Should().BeTrue();
        (await HasRoleAsync(repo, customerClient)).Should().BeFalse("only the controller's accounts are covered");

        var second = await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
        second.GrantedClientRtIds.Should().BeEmpty("the second run finds every account covered");
        (await CountRoleEdgesAsync(repo, pipelineAccount)).Should().Be(1, "no duplicate edge");
    }

    [Fact]
    public async Task AccountCreatedLater_IsPickedUpByTheNextRun()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo);
        await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        var late = await InsertClientAsync(repo, "octo-pipeline-sa-");
        (await PipelineServiceAccountFileRoleGrant.FindAccountsWithoutRoleAsync(tenantContext, () => true))
            .Should().ContainSingle("the detection names the uncovered account");

        var run = await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        run.GrantedClientRtIds.Should().Equal(late.ToString());
        (await PipelineServiceAccountFileRoleGrant.FindAccountsWithoutRoleAsync(tenantContext, () => true)).Should().BeEmpty();
    }

    [Fact]
    public async Task TenantWithoutSystemFiles_IsSkipped()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo);
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");

        var result = await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => false, NullLogger.Instance);

        result.Status.Should().Be(PipelineServiceAccountFileRoleGrantStatus.SkippedNoFilesModel);
        (await HasRoleAsync(repo, account)).Should().BeFalse();
        (await PipelineServiceAccountFileRoleGrant.FindAccountsWithoutRoleAsync(tenantContext, () => false)).Should().BeEmpty();
    }

    [Fact]
    public async Task RoleMissing_WritesNothing_AndTheNextRunGrantsItOnceTheRoleExists()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");

        var first = await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
        first.Status.Should().Be(PipelineServiceAccountFileRoleGrantStatus.RoleMissing);

        await InsertRoleAsync(repo);
        var second = await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
        second.GrantedClientRtIds.Should().Equal(account.ToString());
    }

    [Fact]
    public async Task TenantSetup_RunsTheGrant_ButSkipsTenantsWithoutSystemFilesInTheCkCache()
    {
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo);
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");

        // The production trigger. The fixture tenant has no System.Files model, so the wired probe skips it.
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantContext.TenantId);

        (await HasRoleAsync(repo, account)).Should().BeFalse("no System.Files in this tenant's CK cache");
    }

    [Fact]
    public async Task ConcurrentGrants_NeverLeaveADuplicateEdge()
    {
        // The setup pass and the identity-data consumer can reach the same account at the same moment.
        var (tenantContext, repo) = await CreateTenantAsync();
        await InsertRoleAsync(repo);
        var accounts = new List<OctoObjectId>();
        for (var i = 0; i < 6; i++)
        {
            accounts.Add(await InsertClientAsync(repo, "octo-pipeline-sa-"));
        }

        var runs = Enumerable.Range(0, 6).Select(_ => Task.Run(async () =>
        {
            try
            {
                await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);
            }
            catch (Exception)
            {
                // a lost race may surface as a write conflict; the next run must still converge
            }
        })).ToArray();
        await Task.WhenAll(runs);
        await PipelineServiceAccountFileRoleGrant.EnsureAsync(tenantContext, () => true, NullLogger.Instance);

        foreach (var account in accounts)
        {
            (await CountRoleEdgesAsync(repo, account)).Should().Be(1, "exactly one edge per account after concurrent runs");
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

    private static async Task InsertRoleAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = FileManagementRtId,
            Name = IdentityServiceConstants.FileManagementRole,
            NormalizedName = IdentityServiceConstants.FileManagementRole.ToUpperInvariant(),
            RtWellKnownName = IdentityServiceConstants.FileManagementRole
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

    private static async Task LinkAsync(ITenantRepository repo, OctoObjectId client)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.ApplyChangesAsync(session,
            new[]
            {
                AssociationUpdateInfo.CreateInsert(Client(client), Role(FileManagementRtId),
                    IdentityAssociationConstants.AssignedRoleId)
            }, new OperationResult());
        await session.CommitTransactionAsync();
    }

    private static async Task<int> CountRoleEdgesAsync(ITenantRepository repo, OctoObjectId client)
    {
        using var session = await repo.GetSessionAsync();
        var edges = await repo.GetRtAssociationsAsync(session, Client(client),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        return edges.Items.Count(e => e.TargetRtId == FileManagementRtId);
    }

    private static async Task<bool> HasRoleAsync(ITenantRepository repo, OctoObjectId client) =>
        await CountRoleEdgesAsync(repo, client) > 0;
}
