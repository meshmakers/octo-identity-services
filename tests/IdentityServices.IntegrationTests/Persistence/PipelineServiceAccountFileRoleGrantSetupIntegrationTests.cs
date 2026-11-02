using FluentAssertions;
using IdentityServerPersistence;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6467 / AB#6457: the production trigger of the recurring pipeline service account grant — a tenant setup in
///     a tenant that has System.Files grants FileManagement to the existing <c>octo-pipeline-sa-*</c> accounts and
///     leaves other clients alone; a repeated setup writes nothing new.
/// </summary>
[Collection("Sequential")]
public class PipelineServiceAccountFileRoleGrantSetupIntegrationTests : IClassFixture<IdentityServicesWithFilesModelFixture>
{
    private static readonly OctoObjectId FileManagementRtId = new("660000000000000000000061");

    private readonly IdentityServicesWithFilesModelFixture _fixture;

    public PipelineServiceAccountFileRoleGrantSetupIntegrationTests(IdentityServicesWithFilesModelFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task TenantSetup_GrantsTheRoleToExistingPipelineAccounts_AndASecondSetupAddsNothing()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"pipesa2-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await setup.SetupAsync(tenantId);
        var repo = (await systemContext.GetChildTenantContextAsync(tenantId)).GetTenantRepositoryAsAdmin();
        await InsertRoleAsync(repo);
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");
        var other = await InsertClientAsync(repo, "customer-integration-");

        await setup.SetupAsync(tenantId);

        (await CountEdgesAsync(repo, account)).Should().Be(1, "the setup grants the existing pipeline account");
        (await CountEdgesAsync(repo, other)).Should().Be(0, "other clients are untouched");

        await setup.SetupAsync(tenantId);
        (await CountEdgesAsync(repo, account)).Should().Be(1, "a second setup finds the account covered");
    }

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

    private static async Task<int> CountEdgesAsync(ITenantRepository repo, OctoObjectId client)
    {
        using var session = await repo.GetSessionAsync();
        var edges = await repo.GetRtAssociationsAsync(session,
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), client),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        return edges.Items.Count(e => e.TargetRtId == FileManagementRtId);
    }
}
