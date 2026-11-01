using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#8019: the comparison and the concurrency contract of <see cref="ClientMirrorProvisioningService.ReconcileMirrorsAsync" />.
///     The end-to-end proof (failed sync, job, token refused in the child) is <c>ClientMirrorReconciliationTests</c> in the
///     integration tests.
/// </summary>
public class ClientMirrorReconciliationTests
{
    private const string ParentTenantId = "octosystem";
    private const string ChildTenantId = "acme";
    private const string ClientId = "ci-deploy";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantRepository _parentRepo = Substitute.For<ITenantRepository>();
    private readonly ITenantRepository _childRepo = Substitute.For<ITenantRepository>();
    private readonly IOctoSession _parentSession = Substitute.For<IOctoSession>();
    private readonly IOctoSession _childSession = Substitute.For<IOctoSession>();
    private readonly ClientMirrorProvisioningService _sut;

    public ClientMirrorReconciliationTests()
    {
        _systemContext.TenantId.Returns(ParentTenantId);
        _parentRepo.GetSessionAsync().Returns(_parentSession);
        _childRepo.GetSessionAsync().Returns(_childSession);
        _childRepo.TenantId.Returns(ChildTenantId);
        _systemContext.TryFindTenantRepositoryAsync(ParentTenantId).Returns(_parentRepo);
        _systemContext.TryFindTenantRepositoryAsync(ChildTenantId).Returns(_childRepo);
        _sut = new ClientMirrorProvisioningService(Substitute.For<ILogger<ClientMirrorProvisioningService>>(),
            _systemContext, Substitute.For<ITenantDiscoveryService>());
    }

    // ----- MirrorDiffers ----------------------------------------------------

    [Fact]
    public void MirrorDiffers_SameState_InAnotherSecretOrder_IsFalse()
    {
        var a = Client(("SharedSecret", "h1", null), ("SharedSecret", "h2", null));
        var b = Client(("SharedSecret", "h2", null), ("SharedSecret", "h1", null));

        ClientMirrorProvisioningService.MirrorDiffers(a, b).Should().BeFalse();
    }

    [Fact]
    public void MirrorDiffers_ARemovedSecret_IsTrue()
    {
        var desired = Client(("SharedSecret", "h1", null));
        var current = Client(("SharedSecret", "h1", null), ("SharedSecret", "removed", null));

        ClientMirrorProvisioningService.MirrorDiffers(desired, current).Should().BeTrue();
    }

    [Fact]
    public void MirrorDiffers_AnExpiryChange_IsTrue()
    {
        var desired = Client(("SharedSecret", "h1", DateTime.UtcNow.AddMinutes(-1)));
        var current = Client(("SharedSecret", "h1", null));

        ClientMirrorProvisioningService.MirrorDiffers(desired, current).Should().BeTrue();
    }

    [Fact]
    public void MirrorDiffers_ScopesGrantTypesOrEnabled_AreCompared()
    {
        var baseline = Client();
        var scopes = Client();
        scopes.AllowedScopes = new AttributeStringValueList { "octo_api", "extra" };
        var grants = Client();
        grants.AllowedGrantTypes = new AttributeStringValueList { "client_credentials", "password" };
        var disabled = Client();
        disabled.Enabled = false;

        ClientMirrorProvisioningService.MirrorDiffers(scopes, baseline).Should().BeTrue();
        ClientMirrorProvisioningService.MirrorDiffers(grants, baseline).Should().BeTrue();
        ClientMirrorProvisioningService.MirrorDiffers(disabled, baseline).Should().BeTrue();
    }

    // ----- ReconcileMirrorsAsync --------------------------------------------

    [Fact]
    public async Task Reconcile_ReadsTheChildMirrorBeforeTheParentClient_AndWritesWithTheReadVersion()
    {
        var parent = Client(("SharedSecret", "h1", null));
        var mirror = Client(("SharedSecret", "h1", null), ("SharedSecret", "removed", null));
        mirror.RtVersion = 7;
        SetupRows(Row());
        SetupParentClients(parent);
        SetupChildClients(mirror);

        var result = await _sut.ReconcileMirrorsAsync(ParentTenantId, TestContext.Current.CancellationToken);

        result.MirrorsRepaired.Should().Be(1);
        Received.InOrder(() =>
        {
            _childRepo.GetRtEntitiesByTypeAsync<RtClient>(_childSession, Arg.Any<RtEntityQueryOptions>());
            _parentRepo.GetRtEntitiesByTypeAsync<RtClient>(_parentSession, Arg.Any<RtEntityQueryOptions>());
            _childRepo.ReplaceOneRtEntityByIdAsync(_childSession, mirror.RtId,
                Arg.Is<RtClient>(c => c.ClientSecrets.All(s => s.Value != "removed")), 7UL);
        });
    }

    [Fact]
    public async Task Reconcile_InSync_WritesNothing()
    {
        var parent = Client(("SharedSecret", "h1", null));
        var mirror = Client(("SharedSecret", "h1", null));
        mirror.ProvisionedByParentTenantId = ParentTenantId;
        // A confidential mirror carries its own secret (AB#5061); the repair keeps it, so it is part of "in sync".
        mirror.ClientSecrets.Add(ClientMirrorSecrets.CreateOwnSecretRecord("own-secret-of-the-mirror"));
        SetupRows(Row());
        SetupParentClients(parent);
        SetupChildClients(mirror);

        var result = await _sut.ReconcileMirrorsAsync(ParentTenantId, TestContext.Current.CancellationToken);

        result.Should().Be(new ClientMirrorReconciliationResult(1, 1, 0, 0, 0, 0));
        await _childRepo.DidNotReceiveWithAnyArgs()
            .ReplaceOneRtEntityByIdAsync<RtClient>(default!, default, default!, default(ulong));
        await _parentRepo.DidNotReceiveWithAnyArgs()
            .ReplaceOneRtEntityByIdAsync<RtClientMirror>(default!, default, default!);
    }

    [Fact]
    public async Task Reconcile_AConcurrentWriter_IsAConflict_CountedAsSkipped_AndTheTrackingRowIsNotBumped()
    {
        var parent = Client(("SharedSecret", "h1", null));
        var mirror = Client(("SharedSecret", "stale", null));
        SetupRows(Row());
        SetupParentClients(parent);
        SetupChildClients(mirror);
        _childRepo.ReplaceOneRtEntityByIdAsync(_childSession, mirror.RtId, Arg.Any<RtClient>(), Arg.Any<ulong>())
            .ThrowsAsync(new RtVersionConflictException(new RtEntityId($"System.Identity/Client@{mirror.RtId}"), 0));

        var result = await _sut.ReconcileMirrorsAsync(ParentTenantId, TestContext.Current.CancellationToken);

        result.MirrorsSkipped.Should().Be(1);
        result.MirrorsFailed.Should().Be(0);
        await _parentRepo.DidNotReceiveWithAnyArgs()
            .ReplaceOneRtEntityByIdAsync<RtClientMirror>(default!, default, default!);
    }

    [Fact]
    public async Task Reconcile_ParentClientGone_RemovesOnlyAMirrorOfThisParent_AndTheRow()
    {
        var row = Row();
        var mirror = Client(("SharedSecret", "h1", null));
        mirror.ProvisionedByParentTenantId = ParentTenantId;
        var foreign = Client(("SharedSecret", "h2", null));
        foreign.ProvisionedByParentTenantId = null;
        SetupRows(row);
        SetupParentClients();
        SetupChildClients(mirror, foreign);

        var result = await _sut.ReconcileMirrorsAsync(ParentTenantId, TestContext.Current.CancellationToken);

        result.MirrorsRemoved.Should().Be(1);
        await _childRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClient>(_childSession, mirror.RtId, DeleteOptions.Erase);
        await _childRepo.DidNotReceive().DeleteOneRtEntityByRtIdAsync<RtClient>(_childSession, foreign.RtId, Arg.Any<DeleteOptions>());
        await _parentRepo.Received(1).DeleteOneRtEntityByRtIdAsync<RtClientMirror>(_parentSession, row.RtId, DeleteOptions.Erase);
    }

    [Fact]
    public async Task Reconcile_ChildTenantNotReachable_IsSkipped_AndKeepsTheRow()
    {
        var row = Row();
        row.ChildTenantId = "gone";
        _systemContext.TryFindTenantRepositoryAsync("gone").Returns((ITenantRepository?)null);
        SetupRows(row);

        var result = await _sut.ReconcileMirrorsAsync(ParentTenantId, TestContext.Current.CancellationToken);

        result.MirrorsSkipped.Should().Be(1);
        await _parentRepo.DidNotReceiveWithAnyArgs()
            .DeleteOneRtEntityByRtIdAsync<RtClientMirror>(default!, default, default!);
    }

    // ----- helpers -----------------------------------------------------------

    private static RtClient Client(params (string Type, string Value, DateTime? Expiry)[] secrets)
    {
        var client = new RtClientBuilder().WithClientId(ClientId).WithGrantTypes("client_credentials")
            .WithScopes("octo_api").RequireClientSecret(false).Build();
        client.ClientSecrets ??= new AttributeRecordValueList<RtSecretRecord>();
        foreach (var (type, value, expiry) in secrets)
        {
            client.ClientSecrets.Add(new RtSecretRecord { Type = type, Value = value, ExpirationDateTime = expiry });
        }

        return client;
    }

    private static RtClientMirror Row() => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        ParentClientId = ClientId,
        ParentTenantId = ParentTenantId,
        ChildTenantId = ChildTenantId,
        ProvisionedAt = DateTime.UtcNow,
        SecretHashVersion = 0
    };

    private void SetupRows(params RtClientMirror[] rows)
    {
        var result = Substitute.For<IResultSet<RtClientMirror>>();
        result.Items.Returns(rows);
        _parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(_parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(result);
    }

    private void SetupParentClients(params RtClient[] clients)
    {
        var result = Substitute.For<IResultSet<RtClient>>();
        result.Items.Returns(clients);
        _parentRepo.GetRtEntitiesByTypeAsync<RtClient>(_parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(result);
    }

    private void SetupChildClients(params RtClient[] clients)
    {
        var result = Substitute.For<IResultSet<RtClient>>();
        result.Items.Returns(clients);
        _childRepo.GetRtEntitiesByTypeAsync<RtClient>(_childSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(result);
    }
}
