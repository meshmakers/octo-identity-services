using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// End-to-end checks of the cross-tenant client mirroring (Phase 1). Run against a
/// real MongoDB (Testcontainers) with the full Octo runtime engine wired up. Pin the
/// behaviour every consumer of this feature (CI/CD client roll-out, future Studio UI)
/// depends on: mirrors materialize, secrets propagate, cleanup happens on delete.
/// </summary>
[Collection("Sequential")]
public class ClientMirrorProvisioningIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ClientMirrorProvisioningIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task FlaggedClient_ProvisionsIntoChildTenant_MirrorPersisted()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-fresh-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"flagged-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        var result = await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        result.NewlyProvisioned.Should().BeGreaterThanOrEqualTo(1,
            "the flagged client must reach the new child");
        (await ChildHasClientAsync(systemContext, childTenantId, clientId)).Should().BeTrue();
        (await ParentHasMirrorAsync(systemContext, clientId, childTenantId)).Should().BeTrue();
    }

    [Fact]
    public async Task ProvisionForChildTenantAsync_IsIdempotent()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-idem-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"flagged-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        var first = await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);
        var second = await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        first.NewlyProvisioned.Should().BeGreaterThanOrEqualTo(1);
        // After the second run, the mirror is already there → AlreadyPresent must include it.
        second.AlreadyPresent.Should().BeGreaterThanOrEqualTo(1);
        second.NewlyProvisioned.Should().Be(0,
            "second run must not create a duplicate tracking row");
    }

    [Fact]
    public async Task ProvisionForAllChildTenantsAsync_Backfill_HitsEveryChild()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var clientId = $"backfill-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        // Three pre-existing child tenants — flag is already on, but no per-child
        // provisioning has run yet because we haven't called SetupTenantAsync on them.
        var t1 = await CreateChildTenantAsync($"backfill-a-{Guid.NewGuid():N}".Substring(0, 24));
        var t2 = await CreateChildTenantAsync($"backfill-b-{Guid.NewGuid():N}".Substring(0, 24));
        var t3 = await CreateChildTenantAsync($"backfill-c-{Guid.NewGuid():N}".Substring(0, 24));

        var result = await service.ProvisionForAllChildTenantsAsync(systemContext.TenantId, clientId);

        result.Should().NotBeNull();
        // Multiple sibling tests share the same fixture / system tenant, so other tests'
        // children stick around — only assert that ours are at least covered.
        (await ParentHasMirrorAsync(systemContext, clientId, t1)).Should().BeTrue();
        (await ParentHasMirrorAsync(systemContext, clientId, t2)).Should().BeTrue();
        (await ParentHasMirrorAsync(systemContext, clientId, t3)).Should().BeTrue();
    }

    [Fact]
    public async Task SyncMirrorsForClientAsync_RotatesSecret_BumpsVersion()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-rot-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rotation-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "initial-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var versionBefore = await GetMirrorSecretVersionAsync(systemContext, clientId, childTenantId);

        // Rotate the parent's secret + call sync.
        var rotatedParent = await UpdateParentClientSecretAsync(systemContext, clientId, "rotated-hash");
        var syncResult = await service.SyncMirrorsForClientAsync(systemContext.TenantId, rotatedParent);

        syncResult.MirrorsSynced.Should().BeGreaterThanOrEqualTo(1);
        var versionAfter = await GetMirrorSecretVersionAsync(systemContext, clientId, childTenantId);
        versionAfter.Should().BeGreaterThan(versionBefore);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient.Should().NotBeNull();
        childClient!.ClientSecrets.Select(s => s.Value).Should().Contain("rotated-hash");
    }

    [Fact]
    public async Task RemoveMirrorsForClientAsync_DeletesChildClientAndTrackingRow()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-del-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"to-delete-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var cleanup = await service.RemoveMirrorsForClientAsync(systemContext.TenantId, clientId);

        cleanup.MirrorsRemoved.Should().BeGreaterThanOrEqualTo(1);
        (await ChildHasClientAsync(systemContext, childTenantId, clientId)).Should().BeFalse();
        (await ParentHasMirrorAsync(systemContext, clientId, childTenantId)).Should().BeFalse();
    }

    [Fact]
    public async Task RemoveMirrorsForChildTenantAsync_DropsTrackingForDeletedTenant()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var doomedTenantId = await CreateChildTenantAsync($"child-tdel-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"tdel-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, doomedTenantId);

        var removed = await service.RemoveMirrorsForChildTenantAsync(systemContext.TenantId, doomedTenantId);

        removed.Should().BeGreaterThanOrEqualTo(1);
        (await ParentHasMirrorAsync(systemContext, clientId, doomedTenantId)).Should().BeFalse();
    }

    // ---------- helpers ----------

    private IClientMirrorProvisioningService CreateService(ISystemContext systemContext)
        => new ClientMirrorProvisioningService(NullLogger<ClientMirrorProvisioningService>.Instance, systemContext);

    /// <summary>
    /// Brings the system tenant + the identity CK model online so we can persist
    /// <c>RtClient</c> / <c>RtClientMirror</c> entities. Idempotent across tests.
    /// </summary>
    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        var systemTenantId = _fixture.GetSystemContext().TenantId;
        await setup.SetupAsync(systemTenantId);
    }

    private async Task<string> CreateChildTenantAsync(string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();
        try
        {
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        // SetupAsync imports the identity CK model into the child + provisions baseline
        // resources, mirroring the production startup loop. Without this, inserting an
        // RtClient into the child later throws "RtCkTypeId not found in CkCache".
        // It also runs the mirror-provisioning hook from #4043 — idempotent.
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
        return tenantId;
    }

    private static async Task CreateFlaggedClientAsync(
        ISystemContext systemContext, string clientId, string secretHash = "test-hash")
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            var client = new RtClient
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
            };
            await parentRepo.InsertOneRtEntityAsync(session, client);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    private static async Task<RtClient> UpdateParentClientSecretAsync(
        ISystemContext systemContext, string clientId, string newSecretHash)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            var existing = (await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(
                session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId))).Items
                .First();
            existing.ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
            {
                new() { Value = newSecretHash, Type = "SharedSecret" }
            };
            await parentRepo.ReplaceOneRtEntityByIdAsync(session, existing.RtId, existing);
            await session.CommitTransactionAsync();
            return existing;
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    private static async Task<bool> ChildHasClientAsync(
        ISystemContext systemContext, string childTenantId, string clientId)
    {
        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null) return false;
        using var session = await childRepo.GetSessionAsync();
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.Any();
    }

    private static async Task<RtClient?> FindChildClientAsync(
        ISystemContext systemContext, string childTenantId, string clientId)
    {
        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null) return null;
        using var session = await childRepo.GetSessionAsync();
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private static async Task<bool> ParentHasMirrorAsync(
        ISystemContext systemContext, string clientId, string childTenantId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        var result = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId));
        return result.Items.Any();
    }

    private static async Task<int> GetMirrorSecretVersionAsync(
        ISystemContext systemContext, string clientId, string childTenantId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        var result = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId));
        return result.Items.First().SecretHashVersion;
    }
}
