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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6467 / AB#6457 / AB#8581: the production trigger of the recurring pipeline service account grant — a tenant
///     setup in a tenant that has System.Files grants FileManagement and StreamDataReader to the existing
///     <c>octo-pipeline-sa-*</c> accounts and leaves other clients alone; a repeated setup writes nothing new.
/// </summary>
[Collection("Sequential")]
public class PipelineServiceAccountRoleGrantSetupIntegrationTests : IClassFixture<IdentityServicesWithFilesModelFixture>
{
    private static readonly OctoObjectId FileManagementRtId = new("660000000000000000000061");
    private static readonly OctoObjectId StreamDataReaderRtId = new("66000000000000000000000E");

    private readonly IdentityServicesWithFilesModelFixture _fixture;

    public PipelineServiceAccountRoleGrantSetupIntegrationTests(IdentityServicesWithFilesModelFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task TenantSetup_GrantsBothRolesToExistingPipelineAccounts_AndASecondSetupAddsNothing()
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
        await InsertRoleAsync(repo, FileManagementRtId, IdentityServiceConstants.FileManagementRole);
        await InsertRoleAsync(repo, StreamDataReaderRtId, IdentityServiceConstants.StreamDataReaderRole);
        var account = await InsertClientAsync(repo, "octo-pipeline-sa-");
        var other = await InsertClientAsync(repo, "customer-integration-");

        await setup.SetupAsync(tenantId);

        (await RoleIdsAsync(repo, account)).Should().BeEquivalentTo([FileManagementRtId, StreamDataReaderRtId],
            "the setup grants both baseline roles to the existing pipeline account");
        (await RoleIdsAsync(repo, other)).Should().BeEmpty("other clients are untouched");

        await setup.SetupAsync(tenantId);
        (await RoleIdsAsync(repo, account)).Should().HaveCount(2, "a second setup finds the account covered");
    }

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

    private static async Task<IReadOnlyList<OctoObjectId>> RoleIdsAsync(ITenantRepository repo, OctoObjectId client)
    {
        using var session = await repo.GetSessionAsync();
        var edges = await repo.GetRtAssociationsAsync(session,
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), client),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        return edges.Items.Select(e => e.TargetRtId).ToList();
    }
}
