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
}
