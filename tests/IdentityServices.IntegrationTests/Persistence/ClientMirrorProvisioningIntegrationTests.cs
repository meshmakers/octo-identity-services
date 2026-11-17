using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Http;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Fakes;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// End-to-end checks of the cross-tenant client mirroring (Phase 1). Run against a
/// real MongoDB (Testcontainers) with the full Octo runtime engine wired up. Pin the
/// behaviour every consumer of this feature (CI/CD client roll-out, future Studio UI)
/// depends on: mirrors materialize, secrets propagate, cleanup happens on delete.
/// </summary>
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

        // The child-side mirror must carry the marker so sub-tenant admins know
        // it's not their own client (#4050).
        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient!.ProvisionedByParentTenantId.Should().Be(systemContext.TenantId);
        childClient.AutoProvisionInChildTenants.Should().BeFalse(
            "a mirror must never itself trigger further mirroring");
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

    /// <summary>
    ///     Every identity replica runs the tenant setup when a tenant is created or re-attached by a restore (the restore
    ///     drops the tenant first, which drops its tracking rows). Both replicas then provision the same pair at once. The
    ///     seam holds both runs right before the tracking-row insert, so each has written its child mirror and one insert
    ///     hits the unique index on (client, child). Neither run may fail, and exactly one row and one mirror stay.
    /// </summary>
    [Fact]
    public async Task TwoReplicasProvisioningTheSamePair_RecordOneRowAndOneMirror_WithoutFailing()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-race-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"race-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        var arrived = 0;
        var bothArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task HoldUntilBothArrived(string id, string child)
        {
            if (id != clientId)
            {
                return;
            }

            if (Interlocked.Increment(ref arrived) == 2)
            {
                bothArrived.TrySetResult();
            }

            await bothArrived.Task.WaitAsync(TimeSpan.FromSeconds(30));
        }

        var replicaA = CreateConcreteService(systemContext);
        var replicaB = CreateConcreteService(systemContext);
        replicaA.BeforeTrackingRowWriteForTests = HoldUntilBothArrived;
        replicaB.BeforeTrackingRowWriteForTests = HoldUntilBothArrived;

        // Neither run throws. Whether both inserted a mirror or one replaced the other's depends on the read order;
        // the unit tests pin both branches of the duplicate cleanup.
        await Task.WhenAll(
            Task.Run(() => replicaA.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId)),
            Task.Run(() => replicaB.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId)));

        arrived.Should().Be(2, "both runs reached the tracking-row insert, so one of them hit the unique index");
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(1);
        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(1,
            "the run that lost the row withdraws its second mirror");
        (await FindChildClientAsync(systemContext, childTenantId, clientId))!.ProvisionedByParentTenantId
            .Should().Be(systemContext.TenantId);
    }

    /// <summary>
    ///     The other replica recorded the row after it replaced this run's freshly inserted mirror (same rtId): that
    ///     mirror is the only one and must stay.
    /// </summary>
    [Fact]
    public async Task RowRecordedByAnotherReplica_KeepsTheOnlyMirror()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-rrow-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rrow-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);

        var service = CreateConcreteService(systemContext);
        service.BeforeTrackingRowWriteForTests = async (id, child) =>
        {
            if (id == clientId)
            {
                await InsertTrackingRowAsync(systemContext, id, child);
            }
        };

        var result = await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        result.AlreadyPresent.Should().BeGreaterThanOrEqualTo(1);
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(1);
        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(1);
    }

    /// <summary>
    ///     A tenant delete or restore sends PreDeleteTenant, and one replica drops the tracking rows of the tenant while
    ///     another replica is still provisioning it (tracked pair, so the row is bumped). The bump finds the row gone: no
    ///     failure, and the row of the tenant that is going away is not written again.
    /// </summary>
    [Fact]
    public async Task TrackingRowDroppedByAnotherReplicaDuringProvisioning_DoesNotFail_AndStaysDropped()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-drop-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"drop-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await CreateService(systemContext).ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(1);

        var deletingReplica = CreateService(systemContext);
        var provisioningReplica = CreateConcreteService(systemContext);
        provisioningReplica.BeforeTrackingRowWriteForTests = async (id, child) =>
        {
            if (id == clientId)
            {
                await deletingReplica.RemoveMirrorsForChildTenantAsync(systemContext.TenantId, child);
            }
        };

        var result = await provisioningReplica.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        result.AlreadyPresent.Should().BeGreaterThanOrEqualTo(1);
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(0,
            "the PreDeleteTenant cleanup removed the row; the provisioning must not resurrect it");
    }

    /// <summary>
    ///     A restored child can hold a stale second client of a mirrored id beside the mirror. Every replica that sets the
    ///     tenant up reads both and erases the duplicate. Here one replica erases it between the other replica's read
    ///     and its delete: the late replica must treat the client as removed, not fail the setup, and one mirror stays.
    /// </summary>
    [Fact]
    public async Task DuplicateErasedByAnotherReplicaFirst_DoesNotFailTheProvisioning_AndOneMirrorStays()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-dupe-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"dupe-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await CreateService(systemContext).ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);
        var mirror = await FindChildClientAsync(systemContext, childTenantId, clientId);
        await InsertStaleChildClientAsync(systemContext, childTenantId, clientId);
        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(2);

        var fastReplica = CreateService(systemContext);
        var lateReplica = CreateConcreteService(systemContext);
        var erasedByFastReplica = 0;
        lateReplica.BeforeDuplicateMirrorEraseForTests = async (id, child) =>
        {
            if (id == clientId && Interlocked.Increment(ref erasedByFastReplica) == 1)
            {
                await fastReplica.ProvisionForChildTenantAsync(systemContext.TenantId, child);
            }
        };

        var result = await lateReplica.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        erasedByFastReplica.Should().Be(1, "the late replica read both clients before the fast replica erased one");
        result.AlreadyPresent.Should().BeGreaterThanOrEqualTo(1);
        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(1);
        (await FindChildClientAsync(systemContext, childTenantId, clientId))!.RtId.Should().Be(mirror!.RtId,
            "both replicas keep the same canonical record (the lowest rtId)");
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(1);
    }

    /// <summary>
    ///     A duplicate of the mirror (stale copy of a restore) must not survive the removal of the mirror: every client of
    ///     the id this parent provisioned is erased, not only the first one read; a client of the child itself stays.
    /// </summary>
    [Fact]
    public async Task RemoveMirrorsForClient_ErasesEveryClientOfTheId_DuplicatesIncluded()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-rmdu-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rmdu-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await CreateService(systemContext).ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);
        await InsertStaleChildClientAsync(systemContext, childTenantId, clientId);
        // A client of the child itself with the same id (not provisioned by this parent) is not a mirror.
        await InsertStaleChildClientAsync(systemContext, childTenantId, clientId, provisionedByParentTenantId: "");
        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(3);

        await CreateService(systemContext).RemoveMirrorsForClientAsync(systemContext.TenantId, clientId);

        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(1,
            "both mirrors of the parent are erased, the child's own client stays");
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(0);
    }

    /// <summary>
    ///     Two removals of the same mirror overlap: the first erased the mirror, the second still holds the tracking row
    ///     and finds only a client of the child itself with the same id. That client is not a mirror and stays.
    /// </summary>
    [Fact]
    public async Task SecondRemoval_FindingOnlyTheChildsOwnClient_LeavesItIntact()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-rmow-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rmow-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await CreateService(systemContext).ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);
        // The first removal erased the mirror; the child has its own client of that id.
        await EraseChildClientsAsync(systemContext, childTenantId, clientId);
        await InsertStaleChildClientAsync(systemContext, childTenantId, clientId, provisionedByParentTenantId: "");

        await CreateService(systemContext).RemoveMirrorsForClientAsync(systemContext.TenantId, clientId);

        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(1,
            "the child's own client is not a mirror of this parent");
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(0);
    }

    /// <summary>
    ///     The reconciliation's replace finds the mirror erased by another writer (which also removed the tracking row)
    ///     and inserts it again on the retry. Like every insert it is claimed by the versioned row write: the row is gone,
    ///     so the insert is withdrawn and no untracked client stays behind.
    /// </summary>
    [Fact]
    public async Task Reconciliation_InsertAfterAConcurrentErase_IsWithdrawn_WhenTheRowIsGone()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-rcwd-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rcwd-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await CreateService(systemContext).ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);
        // The parent changes without a sync, so the reconciliation has to replace the mirror.
        await UpdateParentClientSecretAsync(systemContext, clientId, "rotated-hash");

        var service = CreateConcreteService(systemContext);
        var removed = 0;
        service.BeforeMirrorWriteForTests = async (id, child) =>
        {
            if (id == clientId && Interlocked.Increment(ref removed) == 1)
            {
                // Another writer removes the mirror: the child client and its tracking row.
                await CreateService(systemContext).RemoveMirrorsForClientAsync(systemContext.TenantId, id);
            }
        };

        await service.ReconcileMirrorsAsync(systemContext.TenantId, TestContext.Current.CancellationToken);

        removed.Should().BeGreaterThanOrEqualTo(1);
        (await CountTrackingRowsAsync(systemContext, clientId, childTenantId)).Should().Be(0);
        (await CountChildClientsAsync(systemContext, childTenantId, clientId)).Should().Be(0,
            "the re-inserted mirror has no tracking row and is withdrawn");
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

    /// <summary>
    ///     AB#5058 — the token endpoint must refuse to guess a tenant for a mirrored client id.
    ///     Runs the real <see cref="ClientCredentialsTenantProcessor" /> over the real mirror
    ///     bookkeeping in MongoDB: the unit tests stub <c>GetMirrorsAsync</c>, so only this test
    ///     proves that a mirror actually provisioned into a child tenant is what makes the id
    ///     ambiguous.
    /// </summary>
    [Fact]
    public async Task MirroredClient_TokenRequestWithoutAcrValues_IsRefused()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-amb-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"amb-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        // Same client id and secret now live in both tenants — "resolved in the system tenant" no
        // longer implies "belongs to the system tenant".
        (await ChildHasClientAsync(systemContext, childTenantId, clientId)).Should().BeTrue();

        var outcome = await CreateTenantProcessor(systemContext, service)
            .ResolveAsync(clientId, await FindSystemClientAsync(systemContext, clientId));

        outcome.Error.Should().Be(Errors.InvalidRequest, "a mirrored client id has no unambiguous home tenant");
        outcome.TenantId.Should().BeNull("the system tenant must never be stamped on a guess");
    }

    /// <summary>
    ///     AB#5058 backwards-compatibility twin of the test above: a client that was never mirrored
    ///     keeps the AB#5032 behaviour, so the callers that omit <c>acr_values</c> today are unaffected.
    /// </summary>
    [Fact]
    public async Task UnmirroredClient_TokenRequestWithoutAcrValues_StillCarriesTheSystemTenant()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var clientId = $"solo-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateUnflaggedClientAsync(systemContext, clientId);

        var outcome = await CreateTenantProcessor(systemContext, service)
            .ResolveAsync(clientId, await FindSystemClientAsync(systemContext, clientId));

        outcome.Error.Should().BeNull();
        outcome.TenantId.Should().Be(systemContext.TenantId);
    }

    // ---------- AB#5061: per-tenant mirror secrets ----------

    /// <summary>
    ///     The headline guarantee against a real database: the mirror materialized in the child
    ///     tenant carries a secret that is <b>its own</b>, not the parent's copy.
    /// </summary>
    [Fact]
    public async Task MirrorOfConfidentialClient_CarriesAnOwnSecret_DistinctFromTheParents()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-own-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"ownsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "parent-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient.Should().NotBeNull();

        var ownSecret = ClientMirrorSecrets.FindOwnSecret(childClient!);
        ownSecret.Should().NotBeNull("the mirror needs a credential that proves this tenant only");
        ownSecret!.Value.Should().NotBe("parent-hash");

        // ⚠️ …and the inherited parent secret is still there. That is the open half of AB#5061:
        // ci-deploy / octo-ai-adapter / claude-agent still authenticate with it against child
        // tenants, so it cannot be dropped in the same step.
        childClient!.ClientSecrets.Select(s => s.Value).Should().Contain("parent-hash");
    }

    /// <summary>
    ///     🔴 The preservation guarantee end to end. A parent-side secret rotation rewrites every
    ///     mirror from the parent's state; the per-tenant credential must survive it, or every
    ///     rotation would silently lock out everyone who was issued one.
    /// </summary>
    [Fact]
    public async Task ParentSecretRotation_DoesNotInvalidateAnIssuedMirrorSecret()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-keep-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"keepsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "initial-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var issued = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);
        issued.Should().NotBeNull();
        issued!.Secret.Should().NotBeNullOrWhiteSpace();
        var issuedHash = ClientMirrorSecrets.Sha256(issued.Secret!);

        var rotatedParent = await UpdateParentClientSecretAsync(systemContext, clientId, "rotated-hash");
        await service.SyncMirrorsForClientAsync(systemContext.TenantId, rotatedParent);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient!.ClientSecrets.Select(s => s.Value).Should()
            .Contain("rotated-hash", "the parent's new secret still propagates")
            .And.Contain(issuedHash, "the tenant's own credential must survive a parent rotation");
    }

    /// <summary>
    ///     Rotation is the only path that ever reveals a mirror secret, and it invalidates the
    ///     previous one — this is both the distribution mechanism and the rotation mechanism.
    /// </summary>
    [Fact]
    public async Task RotateMirrorSecret_IssuesAFreshValue_AndRetiresThePreviousOne()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-rot2-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"rotsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId, secretHash: "parent-hash");
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var first = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);
        var second = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);

        first!.Secret.Should().NotBe(second!.Secret);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        var storedValues = childClient!.ClientSecrets.Select(s => s.Value).ToList();

        storedValues.Should().Contain(ClientMirrorSecrets.Sha256(second.Secret!));
        storedValues.Should().NotContain(ClientMirrorSecrets.Sha256(first.Secret!),
            "rotation must retire the superseded credential, not accumulate credentials");
        childClient.ClientSecrets.Count(ClientMirrorSecrets.IsOwnSecret).Should().Be(1);
        storedValues.Should().Contain("parent-hash", "rotation must not touch the inherited secret");
    }

    /// <summary>
    ///     A public client — which is every mirrored client in the shipped seed — has no secret to
    ///     scope per tenant, so there is nothing to issue and the request is refused rather than
    ///     silently turning the mirror confidential.
    /// </summary>
    [Fact]
    public async Task RotateMirrorSecret_ForAPublicClient_ReportsNotApplicable()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-pub-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"pubcli-{Guid.NewGuid():N}".Substring(0, 24);
        await CreatePublicFlaggedClientAsync(systemContext, clientId);
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient!.ClientSecrets.Should().BeEmpty("a public client is mirrored unchanged");

        var result = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);

        result.Should().NotBeNull();
        result!.NotApplicable.Should().BeTrue();
        result.Secret.Should().BeNull();
    }

    /// <summary>
    ///     The tracking row is the authority on "this client is mirrored there". Without that guard,
    ///     rotation would mint a secret onto any unrelated client that happens to share the id in
    ///     the named tenant.
    /// </summary>
    [Fact]
    public async Task RotateMirrorSecret_ForAnUntrackedPair_ReturnsNull()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        var childTenantId = await CreateChildTenantAsync($"child-untr-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"untracked-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId);
        // Deliberately never provisioned into that tenant.

        var result = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);

        result.Should().BeNull();
    }

    // ---------- helpers ----------

    // ---------- AB#5065: which secret matched? ----------

    /// <summary>
    ///     The link between AB#5061's writer and AB#5065's reader, proven end to end rather than
    ///     assumed: a mirror provisioned into a real database and read back through the repository
    ///     still carries both secrets and the marker the telemetry classifies on — and the real
    ///     <see cref="OctoApplicationManager" /> then tells the parent's inherited credential apart
    ///     from the tenant's own one.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         🔴 This is the test that catches the dangerous failure: if the provisioning ever
    ///         stopped writing <c>RtSecretRecord.Description</c>, or the round trip dropped it, the
    ///         classification would silently never fire, the inherited-use count would read zero for
    ///         the wrong reason, and step 4 — dropping the inherited secret — would be taken on a
    ///         measurement that never measured anything.
    ///     </para>
    ///     <para>
    ///         🔴 It is also the regression gate for the multi-secret loop. OpenIddict's application
    ///         model holds ONE secret and <c>OpenIddictApplicationStore.GetClientSecretAsync</c>
    ///         returns the first record, so without
    ///         <see cref="OctoApplicationManager.ValidateClientSecretAsync(RtClient,string,CancellationToken)" />
    ///         one of a mirror's two credentials would stop working depending on list order.
    ///     </para>
    /// </remarks>
    [Fact]
    public async Task MirrorSecretUsage_DistinguishesInheritedFromOwn_ThroughTheRealStoredRecords()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();
        var service = CreateService(systemContext);

        const string parentPlaintext = "the-parents-shared-secret";
        var childTenantId = await CreateChildTenantAsync($"child-tel-{Guid.NewGuid():N}".Substring(0, 24));
        var clientId = $"telsec-{Guid.NewGuid():N}".Substring(0, 24);
        await CreateFlaggedClientAsync(systemContext, clientId,
            secretHash: ClientMirrorSecrets.Sha256(parentPlaintext));
        await service.ProvisionForChildTenantAsync(systemContext.TenantId, childTenantId);

        // The only path that ever reveals a mirror's own secret in plaintext.
        var issued = await service.RotateMirrorSecretAsync(systemContext.TenantId, clientId, childTenantId);
        issued!.Secret.Should().NotBeNullOrWhiteSpace();

        var childClient = await FindChildClientAsync(systemContext, childTenantId, clientId);
        childClient!.ClientSecrets.Should().HaveCount(2,
            "the mirror holds the inherited copy and its own until step 4 removes the former");

        var logger = new CapturingLogger<MirrorSecretUsageTelemetry>();
        var httpContextAccessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        httpContextAccessor.HttpContext!.Items[InfrastructureCommon.TenantIdName] = childTenantId;
        var manager = CreateApplicationManager(
            new MirrorSecretUsageTelemetry(httpContextAccessor, logger));

        var inherited = await manager.ValidateClientSecretAsync(
            childClient, parentPlaintext, TestContext.Current.CancellationToken);
        var own = await manager.ValidateClientSecretAsync(
            childClient, issued.Secret!, TestContext.Current.CancellationToken);

        inherited.Should().BeTrue("the inherited secret is still accepted until step 4 removes it");
        own.Should().BeTrue("the mirror's own secret must authenticate even though it is not the first record");

        logger.AllText.Should()
            .Contain($"secretKind={MirrorSecretUsageTelemetry.InheritedSecretKind}")
            .And.Contain($"secretKind={MirrorSecretUsageTelemetry.OwnSecretKind}")
            .And.Contain($"clientId={clientId}")
            .And.Contain($"tenantId={childTenantId}");

        // 🔴 Neither credential nor stored hash may reach a sink, asserted against the rendered text.
        logger.AllText.Should().NotContain(parentPlaintext);
        logger.AllText.Should().NotContain(issued.Secret!);
        logger.AllText.Should().NotContain(ClientMirrorSecrets.Sha256(parentPlaintext));
    }

    /// <summary>
    ///     The production client-authentication seat, with only the OpenIddict plumbing substituted —
    ///     the secret comparison and the classification are the real ones.
    /// </summary>
    private static OctoApplicationManager CreateApplicationManager(IMirrorSecretUsageTelemetry telemetry)
    {
        var options = Substitute.For<IOptionsMonitor<OpenIddictCoreOptions>>();
        options.CurrentValue.Returns(new OpenIddictCoreOptions());

        return new OctoApplicationManager(
            Substitute.For<IOpenIddictApplicationCache<RtClient>>(),
            NullLogger<OpenIddictApplicationManager<RtClient>>.Instance,
            options,
            Substitute.For<IOpenIddictApplicationStore<RtClient>>(),
            telemetry);
    }

    private IClientMirrorProvisioningService CreateService(ISystemContext systemContext)
        => CreateConcreteService(systemContext);

    private static ClientMirrorProvisioningService CreateConcreteService(ISystemContext systemContext)
        => new(NullLogger<ClientMirrorProvisioningService>.Instance, systemContext,
            Substitute.For<IdentityServerPersistence.Services.ITenantDiscoveryService>());

    private static async Task<int> CountTrackingRowsAsync(
        ISystemContext systemContext, string clientId, string childTenantId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        var result = await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId));
        return result.Items.Count();
    }

    private static async Task<int> CountChildClientsAsync(
        ISystemContext systemContext, string childTenantId, string clientId)
    {
        var childRepo = await systemContext.TryFindTenantRepositoryAsync(childTenantId);
        if (childRepo == null) return 0;
        using var session = await childRepo.GetSessionAsync();
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(
            session,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.Count();
    }

    /// <summary>
    ///     A second client of the id in the child, as a restore from an older backup leaves it beside the mirror (an
    ///     older copy of the mirror). Its rtId is generated after the mirror's, so the mirror stays the canonical record.
    /// </summary>
    private static async Task InsertStaleChildClientAsync(ISystemContext systemContext, string childTenantId,
        string clientId, string? provisionedByParentTenantId = null)
    {
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        using var session = await childRepo.GetSessionAsync();
        await childRepo.InsertOneRtEntityAsync(session, new RtClient
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
                new() { Value = "stale-hash", Type = "SharedSecret" }
            },
            ProvisionedByParentTenantId = provisionedByParentTenantId ?? systemContext.TenantId
        });
    }

    private static async Task EraseChildClientsAsync(ISystemContext systemContext, string childTenantId, string clientId)
    {
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        using var session = await childRepo.GetSessionAsync();
        var clients = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        foreach (var client in clients.Items.ToList())
        {
            await childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(session, client.RtId, DeleteOptions.Erase);
        }
    }

    /// <summary>The tracking row another replica records for the pair (as the provisioning writes it).</summary>
    private static async Task InsertTrackingRowAsync(ISystemContext systemContext, string clientId, string childTenantId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        await parentRepo.InsertOneRtEntityAsync(session, new RtClientMirror
        {
            RtId = OctoObjectId.GenerateNewId(),
            ParentClientId = clientId,
            ParentTenantId = systemContext.TenantId,
            ChildTenantId = childTenantId,
            ProvisionedAt = DateTime.UtcNow,
            SecretHashVersion = 0
        });
    }

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

    /// <summary>
    ///     A flagged client of the shape every mirrored client in the shipped
    ///     <c>System.Identity.Bootstrap</c> seed actually has: public, PKCE, no secret.
    /// </summary>
    private static async Task CreatePublicFlaggedClientAsync(
        ISystemContext systemContext, string clientId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await parentRepo.InsertOneRtEntityAsync(session, new RtClient
            {
                RtId = OctoObjectId.GenerateNewId(),
                Enabled = true,
                ClientId = clientId,
                ProtocolType = "oidc",
                RequireClientSecret = false,
                RequirePkce = true,
                AllowedGrantTypes = new AttributeStringValueList { "authorization_code" },
                AllowedScopes = new AttributeStringValueList { "openid", "profile" },
                ClientSecrets = new AttributeRecordValueList<RtSecretRecord>(),
                AutoProvisionInChildTenants = true
            });
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

    /// <summary>
    ///     Wires the real processor over the real mirror bookkeeping. The <c>HttpContextAccessor</c>
    ///     is empty on purpose: that is exactly a <c>client_credentials</c> request which carried no
    ///     <c>acr_values</c>, so the middleware wrote nothing into <c>HttpContext.Items</c> and the
    ///     tenant is what AB#5058 has to decide about. The decision itself runs against MongoDB.
    /// </summary>
    private static ClientCredentialsTenantProcessor CreateTenantProcessor(
        ISystemContext systemContext, IClientMirrorProvisioningService mirrorService) => new(
        mirrorService,
        new HttpContextAccessor(),
        systemContext,
        Substitute.For<IIdentityAuditService>(),
        NullLogger<ClientCredentialsTenantProcessor>.Instance);

    private static async Task<RtClient?> FindSystemClientAsync(ISystemContext systemContext, string clientId)
    {
        var repo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private static async Task CreateUnflaggedClientAsync(ISystemContext systemContext, string clientId)
    {
        var parentRepo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await parentRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
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
                    new() { Value = "test-hash", Type = "SharedSecret" }
                },
                AutoProvisionInChildTenants = false
            });
            await session.CommitTransactionAsync();
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
