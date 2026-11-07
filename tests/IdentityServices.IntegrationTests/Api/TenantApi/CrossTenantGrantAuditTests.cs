using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using IdentityServices.IntegrationTests.Persistence;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8342: every cross-tenant lookup, grant change and exchange lands exactly once in the event log of the target
///     tenant T and once in the source tenant S — through the real pipeline (HTTP for lookup and grants, the real
///     <see cref="TenantExchangeProcessor" /> for the exchange) down to <see cref="IEventRepository" />, which records.
/// </summary>
/// <remarks>
///     Registry: system → T (target, with a login provider to the system tenant, so the system tenant is a registry
///     ancestor), system → S (sibling of T that permits T through the test policy). Each test uses its own caller / user,
///     and the recorded events are filtered by it, so tests sharing the arrangement never see each other's events.
/// </remarks>
public class CrossTenantGrantAuditTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";

    private static readonly SemaphoreSlim ArrangeGate = new(1, 1);
    // Weak: the arrangement must not root a disposed factory (AB#8337, test host memory).
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<CustomWebApplicationFactory, Arrangement>
        Arrangements = new();

    private readonly WebApplicationFactory<Program> _host;
    private readonly List<RecordedEvent> _events = [];
    private volatile bool _failWrites;

    public CrossTenantGrantAuditTests(CustomWebApplicationFactory factory) : base(factory)
    {
        var events = Substitute.For<IEventRepository>();
        events.StoreEventAsync(default!, default, default, default!, default, default, default)
            .ReturnsForAnyArgs(call =>
            {
                if (_failWrites)
                {
                    return Task.FromException(new InvalidOperationException("event store down"));
                }

                Record(new RecordedEvent(call.ArgAt<string>(0), call.ArgAt<RtEventLevelsEnum>(2),
                    call.ArgAt<string>(3), call.ArgAt<string?>(4),
                    (call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                    .ToDictionary(d => d.Key, d => d.Value)));
                return Task.CompletedTask;
            });
        events.StoreErrorEvent(default!, default, default!, default)
            .ReturnsForAnyArgs(call =>
            {
                if (_failWrites)
                {
                    return Task.FromException(new InvalidOperationException("event store down"));
                }

                Record(new RecordedEvent(call.ArgAt<string>(0), RtEventLevelsEnum.Error, call.ArgAt<string>(2), null,
                    []));
                return Task.CompletedTask;
            });
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services => services.AddSingleton(events)));
    }

    /// <summary>Every test builds its own derived host; dispose it (inotify instances, AB#8019).</summary>
    public void Dispose() => _host.Dispose();

    // ------------------------------------------------------------------ lookup

    [Fact]
    public async Task LookupHit_IsRecordedOnceInTargetAndOnceInSource_WithoutEmail()
    {
        var a = await ArrangeAsync();
        var caller = NewCallerName();

        var response = await LookupAsync(caller, a.Target, a.Source, a.Alice.Email);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var events = EventsOf(CrossTenantGrantAuditEvents.Lookup, "actorName", caller);
        AssertOnceInTargetAndSource(events, a.Target, a.Source);
        foreach (var e in events)
        {
            e.Level.Should().Be(RtEventLevelsEnum.Information);
            e.Details.Should().Contain("outcome", "hit").And.Contain("sourceTenantId", a.Source)
                .And.Contain("targetTenantId", a.Target).And.Contain("actorTenantId", a.Target)
                .And.Contain("sourceUserId", a.Alice.Id.ToString()).And.Contain("sourceUserName", a.Alice.UserName);
            e.Text.Should().NotContainEquivalentOf(a.Alice.Email, "the event carries no e-mail address");
        }
    }

    [Fact]
    public async Task LookupMiss_IsRecordedOnceInTargetAndOnceInSource_WithoutTheIdentifier()
    {
        var a = await ArrangeAsync();
        var caller = NewCallerName();
        var identifier = $"ghost-{Guid.NewGuid():N}@missing.example";

        var response = await LookupAsync(caller, a.Target, a.Source, identifier);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var events = EventsOf(CrossTenantGrantAuditEvents.Lookup, "actorName", caller);
        AssertOnceInTargetAndSource(events, a.Target, a.Source);
        foreach (var e in events)
        {
            e.Details.Should().Contain("outcome", "miss").And.NotContainKey("sourceUserId");
            e.Text.Should().NotContainEquivalentOf(identifier).And.NotContainEquivalentOf("ghost-",
                "a missed identifier is never written, not even in part");
        }
    }

    [Fact]
    public async Task LookupMiss_ForANonExistentSourceTenant_IsRecordedOnlyInTarget()
    {
        var a = await ArrangeAsync();
        var caller = NewCallerName();
        var absent = $"absent{Guid.NewGuid():N}"[..20];

        var response = await LookupAsync(caller, a.Target, absent, a.Alice.UserName);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var events = EventsOf(CrossTenantGrantAuditEvents.Lookup, "actorName", caller);
        events.Should().ContainSingle().Which.TenantId.Should().Be(a.Target);
        events[0].Details.Should().Contain("outcome", "miss").And.Contain("sourceTenantId", absent);
        Snapshot().Should().NotContain(e => e.TenantId == absent, "no event goes to a tenant that does not exist");
    }

    // ------------------------------------------------------------------ grants

    [Fact]
    public async Task GrantCreateChangeAndDelete_AreEachRecordedOnceInTargetAndOnceInSource()
    {
        var a = await ArrangeAsync();
        var caller = NewCallerName();
        var client = AdminClient(caller);
        var user = await InsertUserAsync(a.Source, "grant");

        var create = await client.PostAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings",
            new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = a.Source, SourceUserId = user.Id.ToString(), SourceUserName = user.UserName,
                RoleIds = []
            }, TestContext.Current.CancellationToken);
        create.StatusCode.Should().Be(HttpStatusCode.Created,
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var mappingId = (await create.Content.ReadFromJsonAsync<ExternalTenantUserMappingDto>(
            TestContext.Current.CancellationToken))!.Id.ToString()!;

        var created = EventsOf(CrossTenantGrantAuditEvents.GrantCreated, "mappingId", mappingId);
        AssertOnceInTargetAndSource(created, a.Target, a.Source);
        created.Should().AllSatisfy(e =>
        {
            e.Details.Should().Contain("actorName", caller).And.Contain("actorTenantId", a.Target)
                .And.Contain("sourceTenantId", a.Source).And.Contain("targetTenantId", a.Target)
                .And.Contain("sourceUserName", user.UserName).And.ContainKey("groupNames");
            e.Text.Should().NotContainEquivalentOf(user.Email);
        });

        // The mapping joins a T group; change and removal name it.
        var groupName = await AddMappingToNewGroupAsync(a.Target, mappingId);
        var change = await client.PutAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings/{mappingId}",
            new UpdateExternalTenantUserMappingDto { RoleIds = [] }, TestContext.Current.CancellationToken);
        change.StatusCode.Should().Be(HttpStatusCode.OK);

        var changed = EventsOf(CrossTenantGrantAuditEvents.GrantChanged, "mappingId", mappingId);
        AssertOnceInTargetAndSource(changed, a.Target, a.Source);
        changed.Should().AllSatisfy(e => e.Details.Should().Contain("groupNames", groupName));

        var delete = await client.DeleteAsync($"/{a.Target}/v1/ExternalTenantUserMappings/{mappingId}",
            TestContext.Current.CancellationToken);
        delete.StatusCode.Should().Be(HttpStatusCode.OK);

        var removed = EventsOf(CrossTenantGrantAuditEvents.GrantRemoved, "mappingId", mappingId);
        AssertOnceInTargetAndSource(removed, a.Target, a.Source);
        removed.Should().AllSatisfy(e => e.Details.Should().Contain("groupNames", groupName));

        EventsOf(CrossTenantGrantAuditEvents.GrantCreated, "mappingId", mappingId).Should().HaveCount(2,
            "change and removal add no further creation event");
    }

    [Fact]
    public async Task GrantNamingANonPermittedSourceTenant_IsRefused_AndALegacyMappingWritesNothingIntoThatTenant()
    {
        // AB#8343: the create gate refuses a tenant U that is no registry ancestor of T and does not permit T — nothing is
        // stored, no event is written. AB#8436: a mapping naming U that exists from before the gate (inserted directly)
        // still records its change and removal in T only.
        var a = await ArrangeAsync();
        var foreign = await ForeignTenantAsync();
        var caller = NewCallerName();
        var client = AdminClient(caller);
        var fabricated = $"fake{Guid.NewGuid():N}"[..20];
        var user = await InsertUserAsync(foreign, "nope");

        var create = await client.PostAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings",
            new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = foreign, SourceUserId = user.Id.ToString(), SourceUserName = fabricated, RoleIds = []
            }, TestContext.Current.CancellationToken);
        create.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        Snapshot().Should().NotContain(e => e.Category == CrossTenantGrantAuditEvents.GrantCreated &&
                                            e.Text.Contains(fabricated));

        var mappingId = await InsertLegacyMappingAsync(a.Target, foreign, fabricated);
        (await client.PutAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings/{mappingId}",
                new UpdateExternalTenantUserMappingDto { RoleIds = [] }, TestContext.Current.CancellationToken))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await client.DeleteAsync($"/{a.Target}/v1/ExternalTenantUserMappings/{mappingId}",
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);

        foreach (var name in new[] { CrossTenantGrantAuditEvents.GrantChanged, CrossTenantGrantAuditEvents.GrantRemoved })
        {
            EventsOf(name, "mappingId", mappingId).Should().ContainSingle("{0} is recorded in T only", name)
                .Which.TenantId.Should().Be(a.Target);
        }

        Snapshot().Should().NotContain(e => e.TenantId == foreign,
            "a tenant that does not permit T receives no event from T's mappings");
        Snapshot().Where(e => e.Text.Contains(fabricated)).Should().OnlyContain(e => e.TenantId == a.Target);
    }

    [Fact]
    public async Task GrantNamingASourceTenant_ThatListsTheTargetOnItsAllowList_IsRecordedInTargetAndSource()
    {
        // AB#8436 together with AB#8345 and AB#8343: the gate asks the production allow-list (not an arranged test pair).
        // Before U lists T, a grant naming U is refused; after U's administrator puts T on U's allow-list, it is stored
        // and reaches U as well.
        var a = await ArrangeAsync();
        var foreign = await ForeignTenantAsync();
        var caller = NewCallerName();
        var client = AdminClient(caller);
        var user = await InsertUserAsync(foreign, "allow");

        Task<HttpResponseMessage> CreateMappingAsync()
            => client.PostAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings",
                new CreateExternalTenantUserMappingDto
                {
                    SourceTenantId = foreign, SourceUserId = user.Id.ToString(), SourceUserName = user.UserName,
                    RoleIds = []
                }, TestContext.Current.CancellationToken);

        (await CreateMappingAsync()).StatusCode.Should().Be(HttpStatusCode.Forbidden, "U does not list T yet");

        var sourceAdmin = AdminClient(NewCallerName());
        sourceAdmin.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "TenantManagement");
        (await sourceAdmin.PutAsJsonAsync($"/{foreign}/v1/CrossTenantGrantPermissions",
                new CrossTenantGrantPermissionsDto { TargetTenantIds = [a.Target] },
                TestContext.Current.CancellationToken))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var create = await CreateMappingAsync();
        create.StatusCode.Should().Be(HttpStatusCode.Created,
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var after = (await create.Content.ReadFromJsonAsync<ExternalTenantUserMappingDto>(
            TestContext.Current.CancellationToken))!.Id.ToString()!;
        AssertOnceInTargetAndSource(EventsOf(CrossTenantGrantAuditEvents.GrantCreated, "mappingId", after), a.Target,
            foreign);
    }

    [Fact]
    public async Task GrantNamingAnAncestor_IncludingTheSystemTenant_RecordsTheUserNameOfTheSourceRecord_NeverTheRequestsName()
    {
        // AB#8343 (Ariadne's review of #277): the user name of a mapping and of its events comes from S's user record. A
        // free-text name for an ancestor S — here the system tenant — never reaches S's event log; a user id S does not
        // have is refused and writes nothing.
        var a = await ArrangeAsync();
        var caller = NewCallerName();
        var client = AdminClient(caller);
        var real = await InsertUserAsync(NormalizedSystemTenantId, "anc");
        var fabricated = $"fabricated{Guid.NewGuid():N}"[..24];

        var create = await client.PostAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings",
            new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = NormalizedSystemTenantId, SourceUserId = real.Id.ToString(),
                SourceUserName = fabricated, RoleIds = []
            }, TestContext.Current.CancellationToken);
        create.StatusCode.Should().Be(HttpStatusCode.Created,
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var dto = (await create.Content.ReadFromJsonAsync<ExternalTenantUserMappingDto>(
            TestContext.Current.CancellationToken))!;
        dto.SourceUserName.Should().Be(real.UserName, "the stored name is the one of the source tenant's record");

        var created = EventsOf(CrossTenantGrantAuditEvents.GrantCreated, "mappingId", dto.Id.ToString()!);
        AssertOnceInTargetAndSource(created, a.Target, NormalizedSystemTenantId);
        created.Should().AllSatisfy(e => e.Details.Should().Contain("sourceUserName", real.UserName));

        var ghost = await client.PostAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings",
            new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = NormalizedSystemTenantId, SourceUserId = OctoObjectId.GenerateNewId().ToString(),
                SourceUserName = fabricated, RoleIds = []
            }, TestContext.Current.CancellationToken);
        ghost.StatusCode.Should().Be(HttpStatusCode.Forbidden, "the system tenant has no user with that id");

        Snapshot().Should().NotContain(e => e.Text.Contains(fabricated),
            "a name the administrator of T typed is written into no event log, not even T's");
    }

    [Fact]
    public async Task AdminProvisioningCreateAndDelete_AreEachRecordedOnceInTargetAndOnceInSource()
    {
        // The provisioning route (via the system tenant) only takes registry ancestors as source: S = system tenant.
        var a = await ArrangeAsync();
        var caller = NewCallerName();
        var client = AdminClient(caller);
        var sourceUserName = $"prov{Guid.NewGuid():N}"[..20];

        var create = await client.PostAsJsonAsync($"/{NormalizedSystemTenantId}/v1/AdminProvisioning/{a.Target}",
            new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = NormalizedSystemTenantId, SourceUserId = OctoObjectId.GenerateNewId().ToString(),
                SourceUserName = sourceUserName, RoleIds = []
            }, TestContext.Current.CancellationToken);
        create.StatusCode.Should().Be(HttpStatusCode.Created,
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var mappingId = (await create.Content.ReadFromJsonAsync<ExternalTenantUserMappingDto>(
            TestContext.Current.CancellationToken))!.Id.ToString()!;

        var created = EventsOf(CrossTenantGrantAuditEvents.GrantCreated, "mappingId", mappingId);
        AssertOnceInTargetAndSource(created, a.Target, NormalizedSystemTenantId);
        created.Should().AllSatisfy(e => e.Details.Should().Contain("actorName", caller)
            .And.Contain("targetTenantId", a.Target).And.Contain("sourceUserName", sourceUserName));

        var delete = await client.DeleteAsync($"/{NormalizedSystemTenantId}/v1/AdminProvisioning/{a.Target}/{mappingId}",
            TestContext.Current.CancellationToken);
        delete.StatusCode.Should().Be(HttpStatusCode.OK);

        var removed = EventsOf(CrossTenantGrantAuditEvents.GrantRemoved, "mappingId", mappingId);
        AssertOnceInTargetAndSource(removed, a.Target, NormalizedSystemTenantId);
    }

    // ------------------------------------------------------------------ exchange

    [Fact]
    public async Task FirstExchange_IsRecordedOnceInTargetAndOnceInSource_AndNotAgainOnTheNextExchange()
    {
        var a = await ArrangeAsync();
        var user = await InsertUserAsync(NormalizedSystemTenantId, "first");
        var (mappingId, roleName, groupName) = await GrantWithRoleAsync(a.Target, NormalizedSystemTenantId, user);

        var first = await ExchangeAsync(a.Target, NormalizedSystemTenantId, user.Id.ToString());
        first.ShadowUser.Should().NotBeNull("the mapping grants a role: {0}", first.ErrorDescription);

        var events = EventsOf(CrossTenantGrantAuditEvents.FirstExchange, "sourceUserId", user.Id.ToString());
        AssertOnceInTargetAndSource(events, a.Target, NormalizedSystemTenantId);
        events.Should().AllSatisfy(e => e.Details.Should().Contain("mappingId", mappingId)
            .And.Contain("roles", roleName).And.Contain("groupNames", groupName)
            .And.Contain("shadowUserName", first.ShadowUser!.UserName!)
            .And.Contain("sourceTenantId", NormalizedSystemTenantId).And.Contain("targetTenantId", a.Target));

        var second = await ExchangeAsync(a.Target, NormalizedSystemTenantId, user.Id.ToString());
        second.ShadowUser.Should().NotBeNull();
        EventsOf(CrossTenantGrantAuditEvents.FirstExchange, "sourceUserId", user.Id.ToString()).Should()
            .HaveCount(2, "only the exchange that created the shadow user is a first exchange");
    }

    [Fact]
    public async Task RefusedExchange_FromASiblingSource_IsRecordedOnceInTargetAndOnceInSource_NextToTheFailureEvent()
    {
        var a = await ArrangeAsync();
        var user = await InsertUserAsync(a.Source, "refused");

        var outcome = await ExchangeAsync(a.Target, a.Source, user.Id.ToString());

        outcome.Error.Should().NotBeNull("a sibling source without a grant in T is refused (AB#8343)");
        var events = EventsOf(CrossTenantGrantAuditEvents.ExchangeRefused, "sourceUserId", user.Id.ToString());
        AssertOnceInTargetAndSource(events, a.Target, a.Source);
        events.Should().AllSatisfy(e =>
        {
            e.Level.Should().Be(RtEventLevelsEnum.Warning);
            e.Details.Should().Contain("sourceTenantId", a.Source).And.Contain("targetTenantId", a.Target)
                .And.ContainKey("reason");
        });

        // Regression: the existing failure event in T is unchanged (one, error level, same text).
        Snapshot().Where(e => e.Category == null && e.Message.Contains(user.Id.ToString())).Should().ContainSingle()
            .Which.Should().Match<RecordedEvent>(e => e.TenantId == a.Target && e.Level == RtEventLevelsEnum.Error &&
                                                      e.Message.StartsWith("[Token Exchange Failure] "));
    }

    [Fact]
    public async Task RefusedExchange_FromAnAncestorSource_KeepsOnlyTheFailureEvent()
    {
        var a = await ArrangeAsync();
        var user = await InsertUserAsync(NormalizedSystemTenantId, "noprov");

        var outcome = await ExchangeAsync(a.Target, NormalizedSystemTenantId, user.Id.ToString());

        outcome.Error.Should().NotBeNull("the ancestor user holds no role in T");
        EventsOf(CrossTenantGrantAuditEvents.ExchangeRefused, "sourceUserId", user.Id.ToString()).Should().BeEmpty();
        Snapshot().Should().ContainSingle(e => e.Category == null && e.Message.Contains(user.Id.ToString()));
    }

    // ------------------------------------------------------------------ robustness and hygiene

    [Fact]
    public async Task FailingEventStore_NeverBreaksLookupGrantOrExchange()
    {
        var a = await ArrangeAsync();
        var caller = NewCallerName();
        var grantUser = await InsertUserAsync(a.Source, "fail");
        var exchangeUser = await InsertUserAsync(NormalizedSystemTenantId, "failx");
        await GrantWithRoleAsync(a.Target, NormalizedSystemTenantId, exchangeUser);
        _failWrites = true;

        (await LookupAsync(caller, a.Target, a.Source, a.Alice.UserName)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await LookupAsync(caller, a.Target, a.Source, "nobody-at-all")).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);

        var client = AdminClient(caller);
        var create = await client.PostAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings",
            new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = a.Source, SourceUserId = grantUser.Id.ToString(),
                SourceUserName = grantUser.UserName, RoleIds = []
            }, TestContext.Current.CancellationToken);
        create.StatusCode.Should().Be(HttpStatusCode.Created,
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var mappingId = (await create.Content.ReadFromJsonAsync<ExternalTenantUserMappingDto>(
            TestContext.Current.CancellationToken))!.Id;
        (await client.PutAsJsonAsync($"/{a.Target}/v1/ExternalTenantUserMappings/{mappingId}",
                new UpdateExternalTenantUserMappingDto { RoleIds = [] }, TestContext.Current.CancellationToken))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await client.DeleteAsync($"/{a.Target}/v1/ExternalTenantUserMappings/{mappingId}",
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await ExchangeAsync(a.Target, NormalizedSystemTenantId, exchangeUser.Id.ToString())).ShadowUser.Should()
            .NotBeNull("the first exchange succeeds although its audit write fails");
        (await ExchangeAsync(a.Target, a.Source, grantUser.Id.ToString())).Error.Should().NotBeNull();
    }

    [Fact]
    public async Task NoEvent_CarriesAnEmailAddressTokenOrPassword()
    {
        var a = await ArrangeAsync();
        var caller = NewCallerName();
        await LookupAsync(caller, a.Target, a.Source, a.Alice.Email);
        await LookupAsync(caller, a.Target, a.Source, "secret-identifier@nowhere.example");
        var user = await InsertUserAsync(a.Source, "hyg");
        await ExchangeAsync(a.Target, a.Source, user.Id.ToString());

        var ours = Snapshot().Where(e => e.Category != null && CrossTenantGrantAuditEvents.All.Contains(e.Category))
            .ToList();
        ours.Should().NotBeEmpty();
        ours.Should().AllSatisfy(e =>
        {
            e.Text.Should().NotContain("@", "no e-mail address in any cross-tenant audit event");
            e.Text.Should().NotContainEquivalentOf("eyJ", "no JWT");
            e.Text.Should().NotContainEquivalentOf("password").And.NotContainEquivalentOf("token\":")
                .And.NotContainEquivalentOf("secret");
        });
    }

    // ------------------------------------------------------------------ helpers

    private sealed record RecordedEvent(
        string TenantId,
        RtEventLevelsEnum Level,
        string Message,
        string? Category,
        Dictionary<string, string> Details)
    {
        /// <summary>Message and all details as one text, for "never contains" assertions.</summary>
        public string Text => Message + " " + string.Join(" ", Details.Select(d => $"{d.Key}={d.Value}"));
    }

    private void Record(RecordedEvent e)
    {
        lock (_events)
        {
            _events.Add(e);
        }
    }

    private List<RecordedEvent> Snapshot()
    {
        lock (_events)
        {
            return _events.ToList();
        }
    }

    private List<RecordedEvent> EventsOf(string category, string detailKey, string detailValue)
        => Snapshot().Where(e => e.Category == category && e.Details.TryGetValue(detailKey, out var v) &&
                                 v == detailValue).ToList();

    private static void AssertOnceInTargetAndSource(List<RecordedEvent> events, string target, string source)
    {
        events.Should().HaveCount(2, "exactly one event in T and one in S");
        events.Should().ContainSingle(e => e.TenantId == target);
        events.Should().ContainSingle(e => e.TenantId == source);
    }

    private static string NewCallerName() => $"admin{Guid.NewGuid():N}"[..20];

    private HttpClient AdminClient(string userName)
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, OctoObjectId.GenerateNewId().ToString());
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, userName);
        client.DefaultRequestHeaders.Add(TestAuthHandler.EmailHeader, $"{userName}@caller.example");
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, UserManagement);
        return client;
    }

    private Task<HttpResponseMessage> LookupAsync(string caller, string target, string source, string identifier)
        => AdminClient(caller).PostAsJsonAsync($"/{target}/v1/ExternalTenantUserMappings/sourceUserLookup",
            new SourceUserLookupRequestDto { SourceTenantId = source, Identifier = identifier },
            TestContext.Current.CancellationToken);

    /// <summary>Runs the real exchange (after subject token validation) with T wired into the request, as the middleware does.</summary>
    private async Task<TenantExchangeProcessor.ExchangeOutcome> ExchangeAsync(string target, string source,
        string sourceUserId)
    {
        var systemContext = _host.Services.GetRequiredService<ISystemContext>();
        var targetRepo = (await systemContext.TryFindTenantRepositoryAsync(target))!;
        var accessor = _host.Services.GetRequiredService<IHttpContextAccessor>();
        using var scope = _host.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Items[InfrastructureCommon.TenantIdName] = target;
        context.Items[InfrastructureCommon.TenantRepositoryName] = targetRepo;
        accessor.HttpContext = context;
        try
        {
            return await scope.ServiceProvider.GetRequiredService<TenantExchangeProcessor>()
                .ExchangeAsync(source, sourceUserId, target, subjectHasSecondFactor: false);
        }
        finally
        {
            accessor.HttpContext = null;
        }
    }

    private sealed record TestUser(OctoObjectId Id, string UserName, string Email);

    private sealed record Arrangement(string Target, string Source, TestUser Alice);

    private async Task<Arrangement> ArrangeAsync()
    {
        await ArrangeGate.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            if (Arrangements.TryGetValue(Factory, out var existing))
            {
                return existing;
            }

            var target = await CreateTenantAsync("aut", withParentProvider: true);
            var source = await CreateTenantAsync("aus", withParentProvider: false);
            Factory.SourceTenantGrantPolicy.Permit(source, target);
            var alice = await InsertUserAsync(source, "alice");

            var arrangement = new Arrangement(target, source, alice);
            Arrangements.Add(Factory, arrangement);
            return arrangement;
        }
        finally
        {
            ArrangeGate.Release();
        }
    }

    /// <summary>A registered tenant that is no ancestor of T and does not permit it (own per test, so no event leaks in).</summary>
    private Task<string> ForeignTenantAsync() => CreateTenantAsync("auf", withParentProvider: false);

    private async Task<string> CreateTenantAsync(string prefix, bool withParentProvider)
    {
        var tenantId = $"{prefix}{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        }

        if (withParentProvider)
        {
            // The system tenant is the login parent of T: the exchange gate admits its users.
            var repo = (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
            using var session = await repo.GetSessionAsync();
            session.StartTransaction();
            await repo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = $"ParentTenant_{NormalizedSystemTenantId}",
                DisplayName = $"Login via {NormalizedSystemTenantId}",
                IsEnabled = true,
                AllowSelfRegistration = false,
                ParentTenantId = NormalizedSystemTenantId
            });
            await session.CommitTransactionAsync();
        }

        await WaitUntilRegistryKnowsAsync(tenantId);
        return tenantId;
    }

    /// <summary>The services read tenants through the cached registry; wait until it knows a tenant created a moment ago.</summary>
    private async Task WaitUntilRegistryKnowsAsync(string tenantId)
    {
        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    private async Task<ITenantRepository> RepositoryOfAsync(string tenantId)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        return tenantId == NormalizedSystemTenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
    }

    private async Task<TestUser> InsertUserAsync(string tenantId, string prefix)
    {
        var userName = $"{prefix}{Guid.NewGuid():N}"[..20];
        var email = $"{userName}@user.example";
        var repository = await RepositoryOfAsync(tenantId);
        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            FirstName = "Audit",
            LastName = "Subject",
            SecurityStamp = Guid.NewGuid().ToString()
        };
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, user);
        await session.CommitTransactionAsync();
        return new TestUser(user.RtId, userName, email);
    }

    /// <summary>A mapping in T for <paramref name="user" /> of <paramref name="sourceTenantId" /> with one T role and one T group.</summary>
    private async Task<(string MappingId, string RoleName, string GroupName)> GrantWithRoleAsync(string target,
        string sourceTenantId, TestUser user)
    {
        var repo = await RepositoryOfAsync(target);
        var roleName = $"audrole{Guid.NewGuid():N}"[..20];
        var roleId = OctoObjectId.GenerateNewId();
        var mappingId = OctoObjectId.GenerateNewId();
        using (var session = await repo.GetSessionAsync())
        {
            session.StartTransaction();
            await repo.InsertOneRtEntityAsync(session,
                new RtRole { RtId = roleId, Name = roleName, NormalizedName = roleName.ToUpperInvariant() });
            await repo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
            {
                RtId = mappingId,
                SourceTenantId = sourceTenantId,
                SourceUserId = user.Id.ToString(),
                SourceUserName = user.UserName,
                MappedRoleIds = new AttributeStringValueList { roleId.ToString() }
            });
            await session.CommitTransactionAsync();
        }

        var groupName = await AddMappingToNewGroupAsync(target, mappingId.ToString());
        return (mappingId.ToString(), roleName, groupName);
    }

    private async Task<string> AddMappingToNewGroupAsync(string target, string mappingId)
    {
        var repo = await RepositoryOfAsync(target);
        var groupName = $"audgroup{Guid.NewGuid():N}"[..20];
        var groupId = OctoObjectId.GenerateNewId();
        using (var session = await repo.GetSessionAsync())
        {
            session.StartTransaction();
            await repo.InsertOneRtEntityAsync(session,
                new RtGroup { RtId = groupId, GroupName = groupName, NormalizedGroupName = groupName.ToUpperInvariant() });
            await session.CommitTransactionAsync();
        }

        await new GroupStore(new FixedTenantResolver(repo)).AddMemberExternalUserAsync(groupId, mappingId);
        return groupName;
    }

    /// <summary>A mapping inserted directly into T, as one created before the AB#8343 gate could exist.</summary>
    private async Task<string> InsertLegacyMappingAsync(string target, string sourceTenantId, string sourceUserName)
    {
        var repo = await RepositoryOfAsync(target);
        var mappingId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
        {
            RtId = mappingId,
            SourceTenantId = sourceTenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = sourceUserName
        });
        await session.CommitTransactionAsync();
        return mappingId.ToString();
    }
}
