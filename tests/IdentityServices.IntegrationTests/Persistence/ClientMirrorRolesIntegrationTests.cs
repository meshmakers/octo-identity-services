using System.Collections.Concurrent;
using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     a mirrored client gets the roles its original lists in <c>Client.MirrorRoleNames</c>, in every child tenant
///     (nested ones included), idempotently; identity removes only the roles it manages, adopts listed hand grants, honours a
///     tenant's removal (declined) and never serves an untracked copy. Real MongoDB (Testcontainers), the production
///     provisioning service and tenant setup. The fixture seeds no blueprint, so the roles of a child are created in-test.
/// </summary>
[Collection("Sequential")]
public class ClientMirrorRolesIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string Deploy = "CommunicationManagement";
    private const string Viewer = "DashboardViewer";
    private const string Bot = "BotManagement";
    private const string SecretHash = "mirror-roles-secret-hash";
    private static readonly string[] SeedRoles = [Deploy, Viewer, Bot, "TenantManagement", "UserManagement"];

    private readonly IdentityServicesFixture _fixture;
    private readonly CapturingLogger _log = new();
    private readonly IEventRepository _events = Substitute.For<IEventRepository>();

    public ClientMirrorRolesIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task WithoutAList_NothingChanges_ForTheMirror()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("none");
        await CreateConfidentialClientAsync(system, clientId);
        var child = await CreateChildAsync(system);

        await service.ProvisionForChildTenantAsync(system.TenantId, child);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEmpty();
        var row = (await TrackingRowAsync(system, clientId, child))!;
        row.ManagedRoleNames.Should().BeNullOrEmpty();
        row.ManagedMirrorRtId.Should().BeNull("an empty list writes nothing on the tracking row");
    }

    [Fact]
    public async Task NewChild_GetsExactlyTheListedRoles_AndASecondPassWritesNothing()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("new");
        await CreateConfidentialClientAsync(system, clientId);
        (await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct)).Should().NotBeNull();
        var child = await CreateChildAsync(system);

        await service.ProvisionForChildTenantAsync(system.TenantId, child);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        var row = (await TrackingRowAsync(system, clientId, child))!;
        row.ManagedRoleNames.Should().BeEquivalentTo(Deploy);
        row.ManagedMirrorRtId.Should().Be((await MirrorAsync(system, child, clientId))!.RtId.ToString());

        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        var before = (await TrackingRowAsync(system, clientId, child))!;
        var result = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var after = (await TrackingRowAsync(system, clientId, child))!;

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        (await EdgeCountAsync(system, child, clientId)).Should().Be(1, "no second edge");
        result!.Tenants.Should().ContainSingle(t => t.ChildTenantId == child)
            .Which.Outcome.Should().Be(MirrorRoleOutcome.InSync);
        after.RtVersion.Should().Be(before.RtVersion, "a pass with nothing to change does not write the tracking row");
        after.ManagedRoleNames.Should().BeEquivalentTo(Deploy);
        after.ManagedMirrorRtId.Should().Be(before.ManagedMirrorRtId);
    }

    [Fact]
    public async Task NestedGrandchild_GetsTheRolesStraightFromTheSystemTenant_InItsSetup()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("nest");
        await CreateConfidentialClientAsync(system, clientId);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var child = await CreateChildAsync(system);

        var grandchild = await CreateGrandchildAsync(system, child);

        (await MirrorAsync(system, grandchild, clientId))!.ProvisionedByParentTenantId.Should().Be(system.TenantId);
        (await MirrorRolesAsync(system, grandchild, clientId)).Should().BeEquivalentTo([Deploy],
            "the tenant setup of a nested tenant provisions mirror and roles from the system tenant");
    }

    [Fact]
    public async Task MissingRole_IsWarned_ProvisioningSucceeds_AndTheRoleIsAddedOnceItExists()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("miss");
        const string custom = "MirrorRolesCustomRole";
        await InsertRolesAsync(system, system.TenantId, custom);
        await CreateConfidentialClientAsync(system, clientId);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [custom, Deploy], dryRun: false, Ct);
        var child = await CreateChildAsync(system);

        var provisioned = await service.ProvisionForChildTenantAsync(system.TenantId, child);
        var plan = (await service.SetMirrorRolesAsync(system.TenantId, clientId, [custom, Deploy], dryRun: true, Ct))!
            .Tenants.Single(t => t.ChildTenantId == child);

        provisioned.FlaggedClientsConsidered.Should().BeGreaterThan(0);
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        plan.RoleMissing.Should().Equal(custom);
        _log.Messages.Should().Contain(m => m.Level == LogLevel.Warning && m.Text.Contains(custom));

        await InsertRolesAsync(system, child, custom);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy, custom);
    }

    [Fact]
    public async Task ChangingTheList_AddsAndRemovesOnlyManagedRoles_HandSetRolesStayAndAreListed()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("chg");
        await CreateConfidentialClientAsync(system, clientId);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var child = await CreateChildAsync(system);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        await AddEdgeAsync(system, child, clientId, Bot); // set by hand by an operator

        var result = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Viewer], dryRun: false, Ct);

        var tenant = result!.Tenants.Single(t => t.ChildTenantId == child);
        tenant.Outcome.Should().Be(MirrorRoleOutcome.Applied);
        tenant.Added.Should().Equal(Viewer);
        tenant.Removed.Should().Equal(Deploy);
        tenant.HandSet.Should().Equal(Bot);
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Viewer, Bot);
        await _events.Received().StoreInformationEvent(child, RtEventSourcesEnum.IdentityService,
            Arg.Is<string>(m => m.Contains("Mirror roles removed") && m.Contains(Deploy)));
        await _events.Received().StoreInformationEvent(child, RtEventSourcesEnum.IdentityService,
            Arg.Is<string>(m => m.Contains("Mirror roles granted") && m.Contains(Viewer)));
    }

    [Fact]
    public async Task SettingTheList_AdoptsAHandGrant_AndClearingItRemovesTheAdoptedRole_NeverAnotherHandGrant()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("adopt");
        await CreateConfidentialClientAsync(system, clientId);
        var child = await CreateChildAsync(system);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        await AddEdgeAsync(system, child, clientId, Deploy); // a hand grant made before the list existed
        await AddEdgeAsync(system, child, clientId, Bot);

        var plan = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: true, Ct);
        var applied = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);

        plan!.Tenants.Single(t => t.ChildTenantId == child).Adopted.Should().Equal(Deploy);
        var tenant = applied!.Tenants.Single(t => t.ChildTenantId == child);
        tenant.Adopted.Should().Equal(Deploy);
        tenant.Added.Should().BeEmpty();
        (await EdgeCountAsync(system, child, clientId)).Should().Be(2);
        (await TrackingRowAsync(system, clientId, child))!.ManagedRoleNames.Should().BeEquivalentTo(Deploy);

        var cleared = await service.SetMirrorRolesAsync(system.TenantId, clientId, [], dryRun: false, Ct);

        cleared!.Tenants.Single(t => t.ChildTenantId == child).Removed.Should().Equal(Deploy);
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo([Bot],
            "the hand grant the list never named stays");
        (await StoredListAsync(system, clientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task DryRun_WritesNothingAnywhere_AndReturnsThePlanTheWriteExecutes()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("dry");
        await CreateConfidentialClientAsync(system, clientId);
        var child = await CreateChildAsync(system);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        var rowBefore = (await TrackingRowAsync(system, clientId, child))!;

        var plan = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: true, Ct);

        plan!.DryRun.Should().BeTrue();
        var planned = plan.Tenants.Single(t => t.ChildTenantId == child);
        planned.Outcome.Should().Be(MirrorRoleOutcome.Planned);
        planned.Added.Should().Equal(Deploy);
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEmpty();
        (await StoredListAsync(system, clientId)).Should().BeEmpty();
        (await TrackingRowAsync(system, clientId, child))!.RtVersion.Should().Be(rowBefore.RtVersion);

        var applied = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);

        applied!.Tenants.Single(t => t.ChildTenantId == child).Added.Should().Equal(planned.Added);
    }

    [Fact]
    public async Task RoleTheTenantRemoved_IsRecordedAsDeclined_AndNotAddedAgain_ARebuiltMirrorIsGrantedAgain()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("decl");
        await CreateConfidentialClientAsync(system, clientId);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var child = await CreateChildAsync(system);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);

        await RemoveEdgeAsync(system, child, clientId, Deploy); // the tenant administrator takes it away
        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        await service.ReconcileMirrorsAsync(system.TenantId, Ct);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEmpty("the tenant keeps the last word");
        var row = (await TrackingRowAsync(system, clientId, child))!;
        row.DeclinedRoleNames.Should().BeEquivalentTo(Deploy);
        row.ManagedRoleNames.Should().BeNullOrEmpty();
        _log.Messages.Should().Contain(m => m.Level == LogLevel.Warning && m.Text.Contains("declined"));
        await _events.Received().StoreInformationEvent(child, RtEventSourcesEnum.IdentityService,
            Arg.Is<string>(m => m.Contains("Mirror roles declined")));
        var plan = (await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: true, Ct))!
            .Tenants.Single(t => t.ChildTenantId == child);
        plan.Declined.Should().Equal(Deploy);
        plan.Added.Should().BeEmpty();

        // The mirror is deleted and inserted again (another rtId): that is no decision of the tenant.
        await EraseMirrorAsync(system, child, clientId);
        await service.ReconcileMirrorsAsync(system.TenantId, Ct);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        var rebuilt = (await TrackingRowAsync(system, clientId, child))!;
        rebuilt.DeclinedRoleNames.Should().BeNullOrEmpty();
        rebuilt.ManagedMirrorRtId.Should().Be((await MirrorAsync(system, child, clientId))!.RtId.ToString());
    }

    [Fact]
    public async Task ListChangedByAnotherWriter_SinceTheCallerJudgedIt_IsRefused_AndNothingIsWritten()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("conc");
        await CreateConfidentialClientAsync(system, clientId);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Viewer], dryRun: false, Ct);

        // The caller judged its change against an empty list; meanwhile the stored list is [Viewer].
        var act = () => service.SetMirrorRolesAsync(system.TenantId, clientId, [Viewer, Deploy], dryRun: false, Ct,
            expectedStoredRoleNames: []);

        await act.Should().ThrowAsync<ClientMirrorRolesChangedException>();
        (await StoredListAsync(system, clientId)).Should().Equal(Viewer);
    }

    [Fact]
    public async Task TrackedRow_ButTheChildClientLacksThisParentsMarker_GetsNoRoles()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("stray");
        await CreateConfidentialClientAsync(system, clientId);
        var child = await CreateChildAsync(system);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        (await TrackingRowAsync(system, clientId, child)).Should().NotBeNull("the pair is tracked");
        // The child's client of that id now carries another parent's marker (a copy restored from another cluster's dump
        // over the mirror): the row of this parent exists, the client is not its mirror.
        await SetMarkerAsync(system, child, clientId, "another-parent");

        var result = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);

        result!.Tenants.Single(t => t.ChildTenantId == child).Outcome.Should().Be(MirrorRoleOutcome.Skipped);
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task UntrackedCopyWithTheSameClientId_GetsNoRoles()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("untr");
        await CreateConfidentialClientAsync(system, clientId, autoProvision: false);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var child = await CreateChildAsync(system);
        // A copy restored from another cluster's dump: the mirror marker, but no tracking row of this parent.
        await InsertChildClientAsync(system, child, clientId, provisionedBy: system.TenantId);

        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        await service.ReconcileMirrorsAsync(system.TenantId, Ct);
        var result = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEmpty();
        result!.Tenants.Should().NotContain(t => t.ChildTenantId == child);
    }

    [Fact]
    public async Task RoleTheOriginalsTenantDoesNotKnowAsTheSameBuiltInRole_IsNeverGrantedInTheChild()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("refu");
        const string app = "MirrorRolesChildApp";
        const string onlyChild = "MirrorRolesOnlyChild";
        await InsertRolesAsync(system, system.TenantId, app); // a custom role of the same name in the original's tenant
        await CreateConfidentialClientAsync(system, clientId);
        var child = await CreateChildAsync(system);
        await InsertRoleAsync(system, child, app, wellKnownName: app); // an app role installed only in the child
        await InsertRoleAsync(system, child, onlyChild, wellKnownName: null);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);

        // A list that reached the store without the method (a restored database, an older writer).
        var result = await service.SetMirrorRolesAsync(system.TenantId, clientId, [app, onlyChild, Deploy], dryRun: false,
            Ct);

        var tenant = result!.Tenants.Single(t => t.ChildTenantId == child);
        tenant.RoleRefused.Should().Equal(app, onlyChild);
        tenant.Added.Should().Equal(Deploy);
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        _log.Messages.Should().Contain(m => m.Level == LogLevel.Warning && m.Text.Contains(app) &&
                                            m.Text.Contains("not granted"));
    }

    [Fact]
    public async Task RowWriteLosingToAConcurrentBump_StillRecordsTheAddedRoleAsManaged_SoClearingTheListRemovesIt()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("race");
        await CreateConfidentialClientAsync(system, clientId);
        var child = await CreateChildAsync(system);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);
        var bumped = 0;
        service.Roles.BeforeRowWriteForTests = async (id, _) =>
        {
            // Another writer (a rotation, a sync on another replica) bumps the row between its read and this write.
            if (id == clientId && Interlocked.Exchange(ref bumped, 1) == 0)
            {
                await BumpTrackingRowAsync(system, clientId, child);
            }
        };

        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        service.Roles.BeforeRowWriteForTests = null;

        bumped.Should().Be(1, "the concurrent bump ran");
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        (await TrackingRowAsync(system, clientId, child))!.ManagedRoleNames.Should().BeEquivalentTo([Deploy],
            "the row is read again and merged once");

        await service.SetMirrorRolesAsync(system.TenantId, clientId, [], dryRun: false, Ct);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEmpty("the role identity added is managed, not hand-set");
    }

    [Fact]
    public async Task PublicClient_ListThatReachedTheStore_IsNeverAssigned()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("pub");
        await CreateConfidentialClientAsync(system, clientId, publicClient: true);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var child = await CreateChildAsync(system);

        await service.ProvisionForChildTenantAsync(system.TenantId, child);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task FailingRoleWrite_IsLogged_DoesNotFailTheProvisioning_AndTheNextPassConverges()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("fail");
        await CreateConfidentialClientAsync(system, clientId);
        var child = await CreateChildAsync(system);
        service.Roles.BeforeRowWriteForTests = (id, _) =>
            id == clientId ? throw new TimeoutException("injected: tracking row write failed") : Task.CompletedTask;

        var result = await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var act = () => service.ProvisionForChildTenantAsync(system.TenantId, child);

        result!.Tenants.Single(t => t.ChildTenantId == child).Outcome.Should().Be(MirrorRoleOutcome.Failed);
        await act.Should().NotThrowAsync();
        _log.Messages.Should().Contain(m => m.Level == LogLevel.Error && m.Text.Contains(clientId));
        (await TrackingRowAsync(system, clientId, child))!.ManagedRoleNames.Should().BeNullOrEmpty();

        service.Roles.BeforeRowWriteForTests = null;
        await service.ReconcileMirrorsAsync(system.TenantId, Ct);

        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        (await EdgeCountAsync(system, child, clientId)).Should().Be(1);
        (await TrackingRowAsync(system, clientId, child))!.ManagedRoleNames.Should().BeEquivalentTo([Deploy],
            "the edge written before the failure is adopted");
    }

    [Fact]
    public async Task MirrorSecretRotation_LeavesTheRolesAsTheyAre_AndNoLogLineCarriesASecret()
    {
        var (system, service) = await InitializeAsync();
        var clientId = NewClientId("rot");
        await CreateConfidentialClientAsync(system, clientId);
        await service.SetMirrorRolesAsync(system.TenantId, clientId, [Deploy], dryRun: false, Ct);
        var child = await CreateChildAsync(system);
        await service.ProvisionForChildTenantAsync(system.TenantId, child);

        var rotated = await service.RotateMirrorSecretAsync(system.TenantId, clientId, child);
        await service.ReconcileMirrorsAsync(system.TenantId, Ct);

        rotated!.Secret.Should().NotBeNullOrEmpty();
        (await MirrorRolesAsync(system, child, clientId)).Should().BeEquivalentTo(Deploy);
        _log.Messages.Should().NotContain(m => m.Text.Contains(rotated.Secret!) || m.Text.Contains(SecretHash));
    }

    // ---------- helpers ----------

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<(ISystemContext System, ClientMirrorProvisioningService Service)> InitializeAsync()
    {
        await _fixture.InitializeAsync();
        var system = _fixture.GetSystemContext();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(system.TenantId);
        // The names of a list count only as roles the tenant of the original knows (fail-closed).
        await InsertRolesAsync(system, system.TenantId, SeedRoles);
        var service = new ClientMirrorProvisioningService(new TypedLogger(_log), system,
            Substitute.For<ITenantDiscoveryService>(), eventRepository: _events);
        return (system, service);
    }

    private static string NewClientId(string prefix) => $"mr-{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task<string> CreateChildAsync(ISystemContext system)
    {
        var tenantId = $"mrc-{Guid.NewGuid():N}"[..22];
        using (var session = await system.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await system.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await SetupWithRolesAsync(system, tenantId);
        return tenantId;
    }

    private async Task<string> CreateGrandchildAsync(ISystemContext system, string parentId)
    {
        var tenantId = $"mrg-{Guid.NewGuid():N}"[..22];
        var parentContext = await system.GetChildTenantContextAsync(parentId);
        using (var session = await parentContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await parentContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await SetupWithRolesAsync(system, tenantId);
        return tenantId;
    }

    /// <summary>
    ///     First setup imports the identity CK model (the production blueprint would seed the roles), then the roles are
    ///     created and the setup runs again, as an identity restart does.
    /// </summary>
    private async Task SetupWithRolesAsync(ISystemContext system, string tenantId)
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
        await InsertRolesAsync(system, tenantId, SeedRoles);
        await setup.SetupAsync(tenantId);
    }

    private static async Task InsertRolesAsync(ISystemContext system, string tenantId, params string[] names)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        using var session = await repo.GetSessionAsync();
        var existing = (await repo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create())).Items
            .Select(r => r.NormalizedName).ToHashSet(StringComparer.Ordinal);
        foreach (var name in names.Where(n => !existing.Contains(n.ToUpperInvariant())))
        {
            await repo.InsertOneRtEntityAsync(session, new RtRole
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = name,
                NormalizedName = name.ToUpperInvariant()
            });
        }
    }

    private static async Task InsertRoleAsync(ISystemContext system, string tenantId, string name, string? wellKnownName)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        using var session = await repo.GetSessionAsync();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = name,
            NormalizedName = name.ToUpperInvariant(),
            RtWellKnownName = wellKnownName
        });
    }

    private static async Task SetMarkerAsync(ISystemContext system, string tenantId, string clientId, string marker)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        var mirror = (await MirrorAsync(system, tenantId, clientId))!;
        mirror.ProvisionedByParentTenantId = marker;
        using var session = await repo.GetSessionAsync();
        await repo.ReplaceOneRtEntityByIdAsync(session, mirror.RtId, mirror, mirror.RtVersion);
    }

    private static async Task BumpTrackingRowAsync(ISystemContext system, string clientId, string childId)
    {
        var row = (await TrackingRowAsync(system, clientId, childId))!;
        var repo = system.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        await repo.ReplaceOneRtEntityByIdAsync(session, row.RtId, row, row.RtVersion);
    }

    private static async Task CreateConfidentialClientAsync(ISystemContext system, string clientId,
        bool autoProvision = true, bool publicClient = false)
    {
        var repo = system.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = OctoObjectId.GenerateNewId(),
            Enabled = true,
            ClientId = clientId,
            ProtocolType = "oidc",
            RequireClientSecret = !publicClient,
            AllowedGrantTypes = new AttributeStringValueList
                { publicClient ? "authorization_code" : "client_credentials" },
            AllowedScopes = new AttributeStringValueList { "octo_api" },
            ClientSecrets = publicClient
                ? new AttributeRecordValueList<RtSecretRecord>()
                : new AttributeRecordValueList<RtSecretRecord> { new() { Value = SecretHash, Type = "SharedSecret" } },
            AutoProvisionInChildTenants = autoProvision
        });
    }

    private static async Task InsertChildClientAsync(ISystemContext system, string tenantId, string clientId,
        string provisionedBy)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        using var session = await repo.GetSessionAsync();
        await repo.InsertOneRtEntityAsync(session, new RtClient
        {
            RtId = OctoObjectId.GenerateNewId(),
            Enabled = true,
            ClientId = clientId,
            ProtocolType = "oidc",
            RequireClientSecret = true,
            AllowedGrantTypes = new AttributeStringValueList { "client_credentials" },
            ClientSecrets = new AttributeRecordValueList<RtSecretRecord>(),
            ProvisionedByParentTenantId = provisionedBy
        });
    }

    private static async Task<RtClient?> MirrorAsync(ISystemContext system, string tenantId, string clientId)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId)))
            .Items.SingleOrDefault();
    }

    private static async Task<List<RtAssociation>> EdgesAsync(ISystemContext system, string tenantId, string clientId)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        var mirror = (await MirrorAsync(system, tenantId, clientId))!;
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtAssociationsAsync(session, mirror.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId))).Items.ToList();
    }

    private static async Task<int> EdgeCountAsync(ISystemContext system, string tenantId, string clientId) =>
        (await EdgesAsync(system, tenantId, clientId)).Count;

    private static async Task<List<string>> MirrorRolesAsync(ISystemContext system, string tenantId, string clientId)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        var edges = await EdgesAsync(system, tenantId, clientId);
        using var session = await repo.GetSessionAsync();
        var names = new List<string>();
        foreach (var edge in edges)
        {
            var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, edge.TargetRtId);
            names.Add(role?.Name ?? edge.TargetRtId.ToString());
        }

        return names;
    }

    private static async Task<RtRole> RoleAsync(ISystemContext system, string tenantId, string name)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, name.ToUpperInvariant())))
            .Items.Single();
    }

    private static async Task AddEdgeAsync(ISystemContext system, string tenantId, string clientId, string roleName) =>
        await ChangeEdgeAsync(system, tenantId, clientId, roleName, insert: true);

    private static async Task RemoveEdgeAsync(ISystemContext system, string tenantId, string clientId, string roleName) =>
        await ChangeEdgeAsync(system, tenantId, clientId, roleName, insert: false);

    private static async Task ChangeEdgeAsync(ISystemContext system, string tenantId, string clientId, string roleName,
        bool insert)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        var mirror = (await MirrorAsync(system, tenantId, clientId))!.ToRtEntityId();
        var role = (await RoleAsync(system, tenantId, roleName)).ToRtEntityId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var result = new OperationResult();
        await repo.ApplyChangesAsync(session,
        [
            insert
                ? AssociationUpdateInfo.CreateInsert(mirror, role, IdentityAssociationConstants.AssignedRoleId)
                : AssociationUpdateInfo.CreateDelete(mirror, role, IdentityAssociationConstants.AssignedRoleId)
        ], result);
        result.HasErrors.Should().BeFalse();
        await session.CommitTransactionAsync();
    }

    private static async Task EraseMirrorAsync(ISystemContext system, string tenantId, string clientId)
    {
        var repo = (await system.TryFindTenantRepositoryAsync(tenantId))!;
        var mirror = (await MirrorAsync(system, tenantId, clientId))!;
        using var session = await repo.GetSessionAsync();
        await repo.DeleteOneRtEntityByRtIdAsync<RtClient>(session, mirror.RtId, DeleteOptions.Erase);
    }

    private static async Task<RtClientMirror?> TrackingRowAsync(ISystemContext system, string clientId, string childId)
    {
        var repo = system.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtClientMirror>(session, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childId)))
            .Items.SingleOrDefault();
    }

    private static async Task<List<string>> StoredListAsync(ISystemContext system, string clientId)
    {
        var repo = system.GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var client = (await repo.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId))).Items.Single();
        return client.MirrorRoleNames?.ToList() ?? [];
    }

    /// <summary>Keeps the rendered log lines, so a test can assert that none carries a secret.</summary>
    private sealed class CapturingLogger : ILogger
    {
        public ConcurrentQueue<(LogLevel Level, string Text)> Messages { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Messages.Enqueue((logLevel, formatter(state, exception) + (exception == null ? "" : " " + exception.Message)));
    }

    private sealed class TypedLogger(CapturingLogger inner) : ILogger<ClientMirrorProvisioningService>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => inner.Log(logLevel, eventId, state, exception, formatter);
    }
}
