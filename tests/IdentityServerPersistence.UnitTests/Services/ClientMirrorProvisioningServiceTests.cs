using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
/// Pins the parent→child mirror provisioning contract. Important because this is the
/// foundation other Phase 1 issues (#4044 upkeep, #4045 REST backfill) reuse.
/// </summary>
public class ClientMirrorProvisioningServiceTests
{
    private const string ParentTenantId = "octosystem";
    private const string ChildTenantId = "acme";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantRepository _parentRepo = Substitute.For<ITenantRepository>();
    private readonly ITenantRepository _childRepo = Substitute.For<ITenantRepository>();
    private readonly IOctoSession _parentSession = Substitute.For<IOctoSession>();
    private readonly IOctoSession _childSession = Substitute.For<IOctoSession>();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly ClientMirrorProvisioningService _sut;

    public ClientMirrorProvisioningServiceTests()
    {
        _systemContext.TenantId.Returns(ParentTenantId);
        _parentRepo.GetSessionAsync().Returns(_parentSession);
        _childRepo.GetSessionAsync().Returns(_childSession);
        _systemContext.TryFindTenantRepositoryAsync(ParentTenantId).Returns(_parentRepo);
        _systemContext.TryFindTenantRepositoryAsync(ChildTenantId).Returns(_childRepo);

        _sut = new ClientMirrorProvisioningService(
            Substitute.For<ILogger<ClientMirrorProvisioningService>>(),
            _systemContext,
            Substitute.For<ITenantDiscoveryService>(),
            _eventHub);
    }

    [Fact]
    public async Task NoFlaggedClients_ReturnsEmpty_NoInserts()
    {
        SetupParentFlaggedClients(Array.Empty<RtClient>());

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(0, 0, 0));
        await _childRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClient)!);
        await _parentRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClientMirror)!);
    }

    [Fact]
    public async Task FlaggedClientWithoutMirror_ProvisionsMirrorAndTracking()
    {
        var client = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithAutoProvisionInChildTenants()
            .Build();
        SetupParentFlaggedClients(client);
        SetupParentMirrorLookup(client.ClientId, Array.Empty<RtClientMirror>());
        SetupChildClientLookup(client.ClientId, Array.Empty<RtClient>());

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 1, 0));
        // Mirror client inserted in child (no pre-existing client with that ClientId).
        await _childRepo.Received(1).InsertOneRtEntityAsync(
            _childSession,
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"
                && c.AutoProvisionInChildTenants == false));
        // Tracking row inserted in parent.
        await _parentRepo.Received(1).InsertOneRtEntityAsync(
            _parentSession,
            Arg.Is<RtClientMirror>(m => m.ParentClientId == "ci-deploy"
                && m.ParentTenantId == ParentTenantId
                && m.ChildTenantId == ChildTenantId
                && m.SecretHashVersion == 0));
    }

    [Fact]
    public async Task FlaggedClientWithExistingMirror_VerifiesChildSideButSkipsTrackingRow()
    {
        var client = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithAutoProvisionInChildTenants()
            .Build();
        SetupParentFlaggedClients(client);

        var existingMirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithParentTenantId(ParentTenantId)
            .WithChildTenantId(ChildTenantId)
            .Build();
        SetupParentMirrorLookup(client.ClientId, new[] { existingMirror });

        // The child already carries the mirror (matching the tracker). The upsert must still
        // run so any duplicate-clientId stragglers get deduped and any divergent secret/scope
        // state on the child gets pulled back into line with the parent. See the
        // ClientMirrorProvisioningService.ProvisionForChildTenantAsync "already present"
        // branch — re-enabled after the begdemo 2026-06-19 stale-mirror incident.
        var existingChildClient = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .Build();
        SetupChildClientLookup(client.ClientId, new[] { existingChildClient });

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1));
        // Tracking row is NOT re-inserted (the tracker already exists).
        await _parentRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClientMirror)!);
        // Child-side entity IS reconciled with the parent's current state.
        await _childRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClient)!);
        await _childRepo.Received(1).ReplaceOneRtEntityByIdAsync(
            _childSession,
            existingChildClient.RtId,
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"),
            Arg.Any<ulong>());
    }

    [Fact]
    public async Task FlaggedClient_WithExistingClientInChild_ReplacesInsteadOfInserts()
    {
        var client = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithSecret("SharedSecret", "rotated-hash")
            .WithAutoProvisionInChildTenants()
            .Build();
        SetupParentFlaggedClients(client);
        SetupParentMirrorLookup(client.ClientId, Array.Empty<RtClientMirror>());

        // The child already has a (stale) client with the same ClientId — e.g. someone
        // created it manually before flipping AutoProvision on the parent. Provisioning
        // must reconcile it (replace) instead of failing on a duplicate-ClientId index.
        var existingChildClient = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithSecret("SharedSecret", "stale-hash")
            .Build();
        SetupChildClientLookup(client.ClientId, new[] { existingChildClient });

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.NewlyProvisioned.Should().Be(1);
        await _childRepo.Received(1).ReplaceOneRtEntityByIdAsync(
            _childSession,
            existingChildClient.RtId,
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"),
            Arg.Any<ulong>());
        await _childRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClient)!);
    }

    [Fact]
    public async Task ParentEqualsChild_ReturnsEmpty_NoLookups()
    {
        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ParentTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(0, 0, 0));
        await _systemContext.DidNotReceiveWithAnyArgs().TryFindTenantRepositoryAsync(default!);
    }

    [Fact]
    public async Task ParentTenantNotFound_ReturnsEmpty_NoChildLookup()
    {
        _systemContext.TryFindTenantRepositoryAsync(ParentTenantId).Returns((ITenantRepository?)null);

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(0, 0, 0));
        await _parentRepo.DidNotReceiveWithAnyArgs().GetRtEntitiesByTypeAsync<RtClient>(default!, default!);
    }

    [Fact]
    public async Task ChildTenantNotFound_ReturnsEmpty_NoMirrorWritten()
    {
        _systemContext.TryFindTenantRepositoryAsync(ChildTenantId).Returns((ITenantRepository?)null);

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(0, 0, 0));
        await _parentRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClientMirror)!);
    }

    // ----- Two replicas provisioning the same pair (tenant setup after create or restore) -------------

    /// <summary>
    ///     Arranges a flagged client without tracking row and an empty child for the first read; the tracking-row insert
    ///     fails with <paramref name="rowInsertFailure" />. Returns the mirror this run inserts (captured) and sets the
    ///     child's second read to <paramref name="otherWritersMirrors" /> (inserted earlier, so read first) plus that mirror.
    /// </summary>
    private Func<RtClient?> ArrangeRowInsertFailure(Exception rowInsertFailure, params RtClient[] otherWritersMirrors)
    {
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        SetupParentMirrorLookup(client.ClientId, Array.Empty<RtClientMirror>());

        RtClient? inserted = null;
        _childRepo.InsertOneRtEntityAsync(_childSession, Arg.Do<RtClient>(c => inserted = c)).Returns(Task.CompletedTask);
        var reads = 0;
        _childRepo.GetRtEntitiesByTypeAsync<RtClient>(_childSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(_ =>
            {
                var resultSet = Substitute.For<IResultSet<RtClient>>();
                resultSet.Items.Returns(reads++ == 0
                    ? Array.Empty<RtClient>()
                    : otherWritersMirrors.Append(inserted!).ToArray());
                return Task.FromResult(resultSet);
            });
        _parentRepo.InsertOneRtEntityAsync(_parentSession, Arg.Any<RtClientMirror>())
            .Returns(Task.FromException(rowInsertFailure));
        return () => inserted;
    }

    private static DuplicateKeyException RowAlreadyRecorded() =>
        new("Error adding item", typeof(RtClientMirror), new InvalidOperationException("E11000 duplicate key"));

    [Fact]
    public async Task TrackingRowRecordedConcurrently_CountsAsPresent_AndWithdrawsTheSecondMirror()
    {
        var theirs = new RtClientBuilder().WithClientId("ci-deploy").Build();
        var ours = ArrangeRowInsertFailure(RowAlreadyRecorded(), theirs);

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1),
            "the other replica recorded the pair; this run is no failure and provisioned nothing new");
        // The duplicate goes by the rule of the convergence (lowest rtId; the other replica's mirror is older), so a
        // reconciliation pass agrees.
        await _childRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClient>(
            _childSession, ours()!.RtId, Arg.Any<DeleteOptions>());
        await _childRepo.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtClient>(
            _childSession, theirs.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task TrackingRowRecordedConcurrently_KeepsTheInsertedMirror_WhenItIsTheOnlyOne()
    {
        // The other replica replaced this run's insert (same rtId) instead of inserting its own: it is the one mirror.
        ArrangeRowInsertFailure(RowAlreadyRecorded());

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1));
        await _childRepo.DidNotReceiveWithAnyArgs().DeleteOneRtEntityByRtIdAsync<RtClient>(default!, default, default!);
    }

    [Fact]
    public async Task TrackingRowInsert_OtherFailure_StillFailsTheProvisioning()
    {
        ArrangeRowInsertFailure(new InvalidOperationException("database unavailable"));

        var act = () => _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        await act.Should().ThrowAsync<InvalidOperationException>(
            "only a concurrent record of the same pair is expected; every other failure reaches the caller's error log");
        await _childRepo.DidNotReceiveWithAnyArgs().DeleteOneRtEntityByRtIdAsync<RtClient>(default!, default, default!);
    }

    [Fact]
    public async Task TrackedPair_RowRemovedConcurrently_DoesNotFail_AndIsNotWrittenAgain()
    {
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        var row = new RtClientMirrorBuilder().WithParentClientId("ci-deploy").WithParentTenantId(ParentTenantId)
            .WithChildTenantId(ChildTenantId).Build();
        SetupParentMirrorLookup(client.ClientId, new[] { row });
        SetupChildClientLookup(client.ClientId, new[] { new RtClientBuilder().WithClientId("ci-deploy").Build() });
        // Another replica's PreDeleteTenant cleanup removed the row between the read and the bump.
        _parentRepo.ReplaceOneRtEntityByIdAsync(_parentSession, row.RtId, Arg.Any<RtClientMirror>(), Arg.Any<ulong>())
            .Returns(Task.FromException(EntityNotFoundException.IdNotFound(nameof(RtClientMirror), row.RtId.ToString())));

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1));
        await _parentRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClientMirror)!);
    }

    [Fact]
    public async Task TrackedPair_DuplicateErasedByAnotherReplicaFirst_DoesNotFail_AndReplacesTheCanonicalMirror()
    {
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        var row = new RtClientMirrorBuilder().WithParentClientId("ci-deploy").WithParentTenantId(ParentTenantId)
            .WithChildTenantId(ChildTenantId).Build();
        SetupParentMirrorLookup(client.ClientId, new[] { row });
        var first = new RtClientBuilder().WithClientId("ci-deploy").Build();
        var second = new RtClientBuilder().WithClientId("ci-deploy").Build();
        SetupChildClientLookup(client.ClientId, new[] { first, second });
        var canonical = ClientMirrorProvisioningService.SelectCanonicalMirror([first, second]);
        var duplicate = canonical.RtId.Equals(first.RtId) ? second : first;
        // Another replica read the same duplicates and erased this one between our read and our delete.
        _childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(_childSession, duplicate.RtId, Arg.Any<DeleteOptions>())
            .Returns(Task.FromException(EntityNotFoundException.IdNotFound(nameof(RtClient), duplicate.RtId.ToString())));

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1));
        await _childRepo.Received(1).ReplaceOneRtEntityByIdAsync(_childSession, canonical.RtId,
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"), Arg.Any<ulong>());
    }

    [Fact]
    public async Task TrackedPair_CanonicalMirrorErasedByAnotherWriterBeforeTheReplace_ReadsAgainAndInsertsIt()
    {
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        var row = new RtClientMirrorBuilder().WithParentClientId("ci-deploy").WithParentTenantId(ParentTenantId)
            .WithChildTenantId(ChildTenantId).Build();
        SetupParentMirrorLookup(client.ClientId, new[] { row });
        var theirs = new RtClientBuilder().WithClientId("ci-deploy").Build();
        var reads = 0;
        _childRepo.GetRtEntitiesByTypeAsync<RtClient>(_childSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(_ =>
            {
                var resultSet = Substitute.For<IResultSet<RtClient>>();
                resultSet.Items.Returns(reads++ == 0 ? new[] { theirs } : Array.Empty<RtClient>());
                return Task.FromResult(resultSet);
            });
        // The other writer withdrew its insert between our read and our replace.
        _childRepo.ReplaceOneRtEntityByIdAsync(_childSession, theirs.RtId, Arg.Any<RtClient>(), Arg.Any<ulong>())
            .Returns(Task.FromException(EntityNotFoundException.IdNotFound(nameof(RtClient), theirs.RtId.ToString())));

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1));
        await _childRepo.Received(1).InsertOneRtEntityAsync(_childSession,
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"));
    }

    [Fact]
    public async Task TrackedPair_InsertWithdrawn_WhenAnotherWriterErasedItFirst_DoesNotFail()
    {
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        var row = new RtClientMirrorBuilder().WithParentClientId("ci-deploy").WithParentTenantId(ParentTenantId)
            .WithChildTenantId(ChildTenantId).Build();
        SetupParentMirrorLookup(client.ClientId, new[] { row });
        SetupChildClientLookup(client.ClientId, Array.Empty<RtClient>());
        // Another writer re-created the mirror and bumped the row, and its duplicate cleanup erased our insert.
        _parentRepo.ReplaceOneRtEntityByIdAsync(_parentSession, row.RtId, Arg.Any<RtClientMirror>(), Arg.Any<ulong>())
            .Returns(Task.FromException(new RtVersionConflictException(default, 1)));
        _childRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(_childSession, Arg.Any<OctoObjectId>(), Arg.Any<DeleteOptions>())
            .Returns(Task.FromException(EntityNotFoundException.IdNotFound(nameof(RtClient), "erased")));

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1));
        await _childRepo.ReceivedWithAnyArgs(1).DeleteOneRtEntityByRtIdAsync<RtClient>(default!, default, default!);
    }

    [Fact]
    public void SelectCanonicalMirror_DoesNotDependOnTheReadOrder()
    {
        var older = new RtClientBuilder().WithClientId("ci-deploy").Build();
        var newer = new RtClientBuilder().WithClientId("ci-deploy").Build();
        var expected = older.RtId.CompareTo(newer.RtId) < 0 ? older : newer;

        // Two replicas may read the duplicates in different orders; both must keep the same record.
        ClientMirrorProvisioningService.SelectCanonicalMirror([older, newer]).RtId.Should().Be(expected.RtId);
        ClientMirrorProvisioningService.SelectCanonicalMirror([newer, older]).RtId.Should().Be(expected.RtId);
    }

    [Fact]
    public void IsDuplicateKey_FindsTheViolationAlsoBehindAWrapper()
    {
        ClientMirrorProvisioningService.IsDuplicateKey(RowAlreadyRecorded()).Should().BeTrue();
        ClientMirrorProvisioningService.IsDuplicateKey(new InvalidOperationException("bulk import failed",
            RowAlreadyRecorded())).Should().BeTrue();
        ClientMirrorProvisioningService.IsDuplicateKey(new InvalidOperationException("database unavailable"))
            .Should().BeFalse();
    }

    [Theory]
    [InlineData("", ChildTenantId)]
    [InlineData(ParentTenantId, "")]
    [InlineData("  ", ChildTenantId)]
    public async Task BlankTenantId_Throws(string parent, string child)
    {
        Func<Task> act = () => _sut.ProvisionForChildTenantAsync(parent, child);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    private void SetupParentFlaggedClients(params RtClient[] clients)
    {
        var queryResult = Substitute.For<IResultSet<RtClient>>();
        queryResult.Items.Returns(clients);
        _parentRepo.GetRtEntitiesByTypeAsync<RtClient>(
                _parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);
    }

    private void SetupParentMirrorLookup(string parentClientId, RtClientMirror[] mirrors)
    {
        var queryResult = Substitute.For<IResultSet<RtClientMirror>>();
        queryResult.Items.Returns(mirrors);
        _parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
                _parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);
    }

    private void SetupChildClientLookup(string clientId, RtClient[] existingClients)
    {
        var queryResult = Substitute.For<IResultSet<RtClient>>();
        queryResult.Items.Returns(existingClients);
        _childRepo.GetRtEntitiesByTypeAsync<RtClient>(
                _childSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);
    }

    // ----- CorsClientsUpdate (AB#5487) --------------------------------------

    [Fact]
    public async Task NewMirror_PublishesCorsClientsUpdateForTheChildTenant()
    {
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        SetupParentMirrorLookup(client.ClientId, Array.Empty<RtClientMirror>());
        SetupChildClientLookup(client.ClientId, Array.Empty<RtClient>());

        await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        await _eventHub.Received(1).PublishAsync(Arg.Is<CorsClientsUpdate>(m => m.TenantId == ChildTenantId));
    }

    [Fact]
    public async Task NothingProvisioned_PublishesNoCorsClientsUpdate()
    {
        SetupParentFlaggedClients(Array.Empty<RtClient>());

        await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        await _eventHub.DidNotReceiveWithAnyArgs().PublishAsync(default(CorsClientsUpdate)!);
    }

    /// <summary>
    ///     AB#6722: a MassTransit send endpoint waits for the broker without a bound of its own; in CI (no broker on
    ///     localhost) a publish that never completes froze the whole test host for 37 minutes. The wait is bounded.
    /// </summary>
    [Fact]
    public async Task EventHubThatNeverAnswers_DoesNotBlockProvisioning()
    {
        _eventHub.PublishAsync(Arg.Any<CorsClientsUpdate>()).Returns(_ => new TaskCompletionSource().Task);
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        SetupParentMirrorLookup(client.ClientId, Array.Empty<RtClientMirror>());
        SetupChildClientLookup(client.ClientId, Array.Empty<RtClient>());

        var provisioning = _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);
        var finished = await Task.WhenAny(provisioning, Task.Delay(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));

        finished.Should().BeSameAs(provisioning, "the publish wait is bounded (about 5 s)");
        (await provisioning).NewlyProvisioned.Should().Be(1);
    }

    [Fact]
    public async Task EventHubFailure_DoesNotFailProvisioning()
    {
        _eventHub.PublishAsync(Arg.Any<CorsClientsUpdate>()).Returns(_ => throw new InvalidOperationException("broker down"));
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        SetupParentFlaggedClients(client);
        SetupParentMirrorLookup(client.ClientId, Array.Empty<RtClientMirror>());
        SetupChildClientLookup(client.ClientId, Array.Empty<RtClient>());

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.NewlyProvisioned.Should().Be(1);
    }

    [Fact]
    public async Task Sync_PublishesCorsClientsUpdateForEachSyncedChild()
    {
        var client = new RtClientBuilder().WithClientId("ci-deploy").WithAutoProvisionInChildTenants().Build();
        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy").WithParentTenantId(ParentTenantId).WithChildTenantId(ChildTenantId).Build();
        SetupParentMirrorLookup(client.ClientId, new[] { mirror });
        SetupChildClientLookup(client.ClientId, Array.Empty<RtClient>());

        await _sut.SyncMirrorsForClientAsync(ParentTenantId, client);

        await _eventHub.Received(1).PublishAsync(Arg.Is<CorsClientsUpdate>(m => m.TenantId == ChildTenantId));
    }

    [Fact]
    public async Task RemoveForClient_PublishesCorsClientsUpdateForTheChildTenant()
    {
        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy").WithChildTenantId(ChildTenantId).Build();
        SetupParentMirrorLookup("ci-deploy", new[] { mirror });
        SetupChildClientLookup("ci-deploy", new[] { new RtClientBuilder().WithClientId("ci-deploy").Build() });

        await _sut.RemoveMirrorsForClientAsync(ParentTenantId, "ci-deploy");

        await _eventHub.Received(1).PublishAsync(Arg.Is<CorsClientsUpdate>(m => m.TenantId == ChildTenantId));
    }

    // ----- SyncMirrorsForClientAsync ---------------------------------------

    [Fact]
    public async Task Sync_NoMirrorsForClient_ReturnsZeroNoUpdates()
    {
        var client = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithAutoProvisionInChildTenants()
            .Build();
        SetupParentMirrorLookup(client.ClientId, Array.Empty<RtClientMirror>());

        var result = await _sut.SyncMirrorsForClientAsync(ParentTenantId, client);

        result.Should().Be(new ClientMirrorSyncResult(0, 0));
        await _childRepo.DidNotReceiveWithAnyArgs()
            .ReplaceOneRtEntityByIdAsync(default!, default!, default(RtClient)!, default(ulong));
    }

    [Fact]
    public async Task Sync_OneMirror_PropagatesAndBumpsVersion()
    {
        var client = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithSecret("SharedSecret", "rotated-hash")
            .WithAutoProvisionInChildTenants()
            .Build();
        var existingMirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithParentTenantId(ParentTenantId)
            .WithChildTenantId(ChildTenantId)
            .WithSecretHashVersion(2)
            .Build();
        SetupParentMirrorLookup(client.ClientId, new[] { existingMirror });

        // Child has an existing mirror client (from a previous provisioning) → replace path.
        var staleChildClient = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithSecret("SharedSecret", "stale-hash")
            .Build();
        SetupChildClientLookup(client.ClientId, new[] { staleChildClient });

        var result = await _sut.SyncMirrorsForClientAsync(ParentTenantId, client);

        result.Should().Be(new ClientMirrorSyncResult(1, 0));
        await _childRepo.Received(1).ReplaceOneRtEntityByIdAsync(
            _childSession,
            staleChildClient.RtId,
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"),
            Arg.Any<ulong>());
        // AB#8054: the counter bump is version-checked (the row's version as read right before the write).
        await _parentRepo.Received(1).ReplaceOneRtEntityByIdAsync(
            _parentSession,
            existingMirror.RtId,
            Arg.Is<RtClientMirror>(m => m.SecretHashVersion == 3),
            existingMirror.RtVersion);
    }

    [Fact]
    public async Task Sync_ChildTenantMissing_CountsAsFailedNoCrash()
    {
        var client = new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithAutoProvisionInChildTenants()
            .Build();
        var lostChildMirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithChildTenantId("gone-tenant")
            .Build();
        SetupParentMirrorLookup(client.ClientId, new[] { lostChildMirror });
        _systemContext.TryFindTenantRepositoryAsync("gone-tenant").Returns((ITenantRepository?)null);

        var result = await _sut.SyncMirrorsForClientAsync(ParentTenantId, client);

        result.Should().Be(new ClientMirrorSyncResult(0, 1));
    }

    // ----- RemoveMirrorsForClientAsync -------------------------------------

    [Fact]
    public async Task RemoveForClient_NoMirrors_ReturnsZero()
    {
        SetupParentMirrorLookup("ci-deploy", Array.Empty<RtClientMirror>());

        var result = await _sut.RemoveMirrorsForClientAsync(ParentTenantId, "ci-deploy");

        result.Should().Be(new ClientMirrorCleanupResult(0, 0));
    }

    [Fact]
    public async Task RemoveForClient_DropsChildClientAndTrackingRow()
    {
        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithChildTenantId(ChildTenantId)
            .Build();
        SetupParentMirrorLookup("ci-deploy", new[] { mirror });
        var childClient = new RtClientBuilder().WithClientId("ci-deploy").Build();
        childClient.ProvisionedByParentTenantId = ParentTenantId;
        SetupChildClientLookup("ci-deploy", new[] { childClient });

        var result = await _sut.RemoveMirrorsForClientAsync(ParentTenantId, "ci-deploy");

        result.Should().Be(new ClientMirrorCleanupResult(1, 0));
        await _childRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClient>(
            _childSession, childClient.RtId, Arg.Any<DeleteOptions>());
        await _parentRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
            _parentSession, mirror.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task RemoveForClient_LeavesAClientOfTheChildItself_WithTheSameId()
    {
        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithChildTenantId(ChildTenantId)
            .Build();
        SetupParentMirrorLookup("ci-deploy", new[] { mirror });
        // Not provisioned by this parent: e.g. a concurrent removal already erased the mirror, only the child's own
        // client of that id is left.
        var ownClient = new RtClientBuilder().WithClientId("ci-deploy").Build();
        SetupChildClientLookup("ci-deploy", new[] { ownClient });

        var result = await _sut.RemoveMirrorsForClientAsync(ParentTenantId, "ci-deploy");

        result.Should().Be(new ClientMirrorCleanupResult(1, 0));
        await _childRepo.DidNotReceiveWithAnyArgs().DeleteOneRtEntityByRtIdAsync<RtClient>(default!, default, default!);
        await _parentRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
            _parentSession, mirror.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task RemoveForClient_ChildTenantGone_StillRemovesTrackingRow()
    {
        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithChildTenantId("gone-tenant")
            .Build();
        SetupParentMirrorLookup("ci-deploy", new[] { mirror });
        _systemContext.TryFindTenantRepositoryAsync("gone-tenant").Returns((ITenantRepository?)null);

        var result = await _sut.RemoveMirrorsForClientAsync(ParentTenantId, "ci-deploy");

        result.MirrorsRemoved.Should().Be(1);
        await _parentRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
            _parentSession, mirror.RtId, Arg.Any<DeleteOptions>());
    }

    // ----- RemoveMirrorsForChildTenantAsync --------------------------------

    [Fact]
    public async Task RemoveForChildTenant_DropsAllRowsPointingAtTenant()
    {
        var mirrorA = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithChildTenantId(ChildTenantId)
            .Build();
        var mirrorB = new RtClientMirrorBuilder()
            .WithParentClientId("ci-watcher")
            .WithChildTenantId(ChildTenantId)
            .Build();
        var queryResult = Substitute.For<IResultSet<RtClientMirror>>();
        queryResult.Items.Returns(new[] { mirrorA, mirrorB });
        _parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
                _parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);

        var removed = await _sut.RemoveMirrorsForChildTenantAsync(ParentTenantId, ChildTenantId);

        removed.Should().Be(2);
        await _parentRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
            _parentSession, mirrorA.RtId, Arg.Any<DeleteOptions>());
        await _parentRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
            _parentSession, mirrorB.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task RemoveForChildTenant_RowAlreadyDroppedByAnotherReplica_LogsNoError()
    {
        var logger = Substitute.For<ILogger<ClientMirrorProvisioningService>>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sut = new ClientMirrorProvisioningService(
            logger, _systemContext, Substitute.For<ITenantDiscoveryService>(), _eventHub);
        var gone = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithChildTenantId(ChildTenantId)
            .Build();
        var present = new RtClientMirrorBuilder()
            .WithParentClientId("ci-watcher")
            .WithChildTenantId(ChildTenantId)
            .Build();
        SetupChildTenantMirrorQuery(gone, present);
        _parentRepo.DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
                _parentSession, gone.RtId, Arg.Any<DeleteOptions>())
            .Returns(Task.FromException(EntityNotFoundException.IdNotFound(nameof(RtClientMirror), gone.RtId.ToString())));

        var removed = await sut.RemoveMirrorsForChildTenantAsync(ParentTenantId, ChildTenantId);

        removed.Should().Be(1);
        await _parentRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
            _parentSession, present.RtId, Arg.Any<DeleteOptions>());
        LoggedAt(logger, LogLevel.Error).Should().Be(0);
        LoggedAt(logger, LogLevel.Debug).Should().Be(1);
    }

    [Fact]
    public async Task RemoveForChildTenant_RealDropFailure_StillLogsError()
    {
        var logger = Substitute.For<ILogger<ClientMirrorProvisioningService>>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        var sut = new ClientMirrorProvisioningService(
            logger, _systemContext, Substitute.For<ITenantDiscoveryService>(), _eventHub);
        var mirror = new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithChildTenantId(ChildTenantId)
            .Build();
        SetupChildTenantMirrorQuery(mirror);
        _parentRepo.DeleteOneRtEntityByRtIdAsync<RtClientMirror>(
                _parentSession, mirror.RtId, Arg.Any<DeleteOptions>())
            .Returns(Task.FromException(new InvalidOperationException("database unavailable")));

        var removed = await sut.RemoveMirrorsForChildTenantAsync(ParentTenantId, ChildTenantId);

        removed.Should().Be(0);
        LoggedAt(logger, LogLevel.Error).Should().Be(1);
    }

    private void SetupChildTenantMirrorQuery(params RtClientMirror[] mirrors)
    {
        var queryResult = Substitute.For<IResultSet<RtClientMirror>>();
        queryResult.Items.Returns(mirrors);
        _parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(
                _parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);
    }

    private static int LoggedAt(ILogger logger, LogLevel level) =>
        logger.ReceivedCalls().Count(c =>
            c.GetMethodInfo().Name == nameof(ILogger.Log) && (LogLevel)c.GetArguments()[0]! == level);

    [Fact]
    public async Task RemoveForChildTenant_ParentMissing_ReturnsZero()
    {
        _systemContext.TryFindTenantRepositoryAsync(ParentTenantId).Returns((ITenantRepository?)null);

        var removed = await _sut.RemoveMirrorsForChildTenantAsync(ParentTenantId, ChildTenantId);

        removed.Should().Be(0);
    }
}
