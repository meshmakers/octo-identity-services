using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
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
    private readonly ClientMirrorProvisioningService _sut;

    public ClientMirrorProvisioningServiceTests()
    {
        _parentRepo.GetSessionAsync().Returns(_parentSession);
        _childRepo.GetSessionAsync().Returns(_childSession);
        _systemContext.TryFindTenantRepositoryAsync(ParentTenantId).Returns(_parentRepo);
        _systemContext.TryFindTenantRepositoryAsync(ChildTenantId).Returns(_childRepo);

        _sut = new ClientMirrorProvisioningService(
            Substitute.For<ILogger<ClientMirrorProvisioningService>>(),
            _systemContext);
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
    public async Task FlaggedClientWithExistingMirror_SkipsAsAlreadyPresent()
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

        var result = await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        result.Should().Be(new ClientMirrorProvisioningResult(1, 0, 1));
        await _childRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClient)!);
        await _parentRepo.DidNotReceiveWithAnyArgs().InsertOneRtEntityAsync(default!, default(RtClientMirror)!);
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
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"));
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
            .ReplaceOneRtEntityByIdAsync(default!, default!, default(RtClient)!);
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
            Arg.Is<RtClient>(c => c.ClientId == "ci-deploy"));
        await _parentRepo.Received(1).ReplaceOneRtEntityByIdAsync(
            _parentSession,
            existingMirror.RtId,
            Arg.Is<RtClientMirror>(m => m.SecretHashVersion == 3));
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
        SetupChildClientLookup("ci-deploy", new[] { childClient });

        var result = await _sut.RemoveMirrorsForClientAsync(ParentTenantId, "ci-deploy");

        result.Should().Be(new ClientMirrorCleanupResult(1, 0));
        await _childRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClient>(
            _childSession, childClient.RtId, Arg.Any<DeleteOptions>());
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
    public async Task RemoveForChildTenant_ParentMissing_ReturnsZero()
    {
        _systemContext.TryFindTenantRepositoryAsync(ParentTenantId).Returns((ITenantRepository?)null);

        var removed = await _sut.RemoveMirrorsForChildTenantAsync(ParentTenantId, ChildTenantId);

        removed.Should().Be(0);
    }
}
