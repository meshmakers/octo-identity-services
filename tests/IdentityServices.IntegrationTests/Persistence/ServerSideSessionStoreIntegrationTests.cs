using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// Real-Mongo round-trip tests for <see cref="ServerSideSessionStore"/>.
/// Exercises the full AutoMapper configuration wired by AddOctoIdentityPersistence.
/// </summary>
[Collection("Sequential")]
public class ServerSideSessionStoreIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public ServerSideSessionStoreIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        var systemTenantId = _fixture.GetSystemContext().TenantId;
        await setup.SetupAsync(systemTenantId);
    }

    private ServerSideSessionStore CreateStore()
    {
        var systemContext = _fixture.GetSystemContext();
        var repo = systemContext.GetSystemTenantRepositoryAsAdmin();
        return new ServerSideSessionStore(
            new FixedTenantResolver(repo),
            systemContext,
            _fixture.GetService<IMapper>());
    }

    [Fact]
    public async Task CreateAndGet_RoundTrips_AllProperties()
    {
        var ct = TestContext.Current.CancellationToken;
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var key = $"sess-{Guid.NewGuid():N}";
        var now = DateTime.UtcNow;
        var session = new ServerSideSession
        {
            Key = key,
            Scheme = "idsrv",
            SubjectId = $"sub-{Guid.NewGuid():N}",
            SessionId = $"sid-{Guid.NewGuid():N}",
            DisplayName = "Test User",
            Created = now,
            Renewed = now,
            Expires = now.AddHours(1),
            Ticket = "ticket-payload"
        };

        var store = CreateStore();
        await store.CreateSessionAsync(session, ct);

        var retrieved = await store.GetSessionAsync(key, ct);

        retrieved.Should().NotBeNull();
        retrieved!.Key.Should().Be(session.Key);
        retrieved.Scheme.Should().Be(session.Scheme);
        retrieved.SubjectId.Should().Be(session.SubjectId);
        retrieved.SessionId.Should().Be(session.SessionId);
        retrieved.DisplayName.Should().Be(session.DisplayName);
        retrieved.Ticket.Should().Be(session.Ticket);
        retrieved.Created.Should().BeCloseTo(session.Created, TimeSpan.FromSeconds(1));
        retrieved.Renewed.Should().BeCloseTo(session.Renewed, TimeSpan.FromSeconds(1));
        retrieved.Expires.Should().NotBeNull();
        retrieved.Expires!.Value.Should().BeCloseTo(session.Expires!.Value, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task GetSessionAsync_Expired_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var key = $"sess-{Guid.NewGuid():N}";
        var session = new ServerSideSession
        {
            Key = key,
            Scheme = "idsrv",
            SubjectId = $"sub-{Guid.NewGuid():N}",
            SessionId = $"sid-{Guid.NewGuid():N}",
            Created = DateTime.UtcNow,
            Renewed = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(-1),
            Ticket = "expired-ticket"
        };

        var store = CreateStore();
        await store.CreateSessionAsync(session, ct);

        var retrieved = await store.GetSessionAsync(key, ct);

        retrieved.Should().BeNull("expired sessions must not authenticate");
    }

    [Fact]
    public async Task UpdateSessionAsync_RenewsTicketAndExpiry()
    {
        var ct = TestContext.Current.CancellationToken;
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var key = $"sess-{Guid.NewGuid():N}";
        var subjectId = $"sub-{Guid.NewGuid():N}";
        var original = new ServerSideSession
        {
            Key = key,
            Scheme = "idsrv",
            SubjectId = subjectId,
            SessionId = $"sid-{Guid.NewGuid():N}",
            Created = DateTime.UtcNow,
            Renewed = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddHours(1),
            Ticket = "original-ticket"
        };

        var store = CreateStore();
        await store.CreateSessionAsync(original, ct);

        var updated = new ServerSideSession
        {
            Key = key,
            Scheme = "idsrv",
            SubjectId = subjectId,
            SessionId = original.SessionId,
            Created = original.Created,
            Renewed = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddHours(2),
            Ticket = "renewed-ticket"
        };

        await store.UpdateSessionAsync(updated, ct);

        var retrieved = await store.GetSessionAsync(key, ct);

        retrieved.Should().NotBeNull();
        retrieved!.Ticket.Should().Be("renewed-ticket");
        retrieved.Expires.Should().NotBeNull();
        retrieved.Expires!.Value.Should().BeCloseTo(updated.Expires!.Value, TimeSpan.FromSeconds(1));

        // Assert only ONE document exists for this key (no duplicates after update)
        var systemContext = _fixture.GetSystemContext();
        var repo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var octoSession = await repo.GetSessionAsync();
        var all = await repo.GetRtEntitiesByTypeAsync<RtServerSideSession>(
            octoSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtServerSideSession.SessionKey), FieldFilterOperator.Equals, key));
        all.Items.Count().Should().Be(1, "update must not create a second document");
    }

    [Fact]
    public async Task DeleteSessionAsync_RemovesDocument()
    {
        var ct = TestContext.Current.CancellationToken;
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var key = $"sess-{Guid.NewGuid():N}";
        var session = new ServerSideSession
        {
            Key = key,
            Scheme = "idsrv",
            SubjectId = $"sub-{Guid.NewGuid():N}",
            SessionId = $"sid-{Guid.NewGuid():N}",
            Created = DateTime.UtcNow,
            Renewed = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddHours(1),
            Ticket = "ticket"
        };

        var store = CreateStore();
        await store.CreateSessionAsync(session, ct);

        // Verify it exists first
        var before = await store.GetSessionAsync(key, ct);
        before.Should().NotBeNull();

        await store.DeleteSessionAsync(key, ct);

        var after = await store.GetSessionAsync(key, ct);
        after.Should().BeNull("deleted session must not be retrievable");
    }

    [Fact]
    public async Task GetSessionsAsync_FiltersBySubject()
    {
        var ct = TestContext.Current.CancellationToken;
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var subjectA = $"sub-a-{Guid.NewGuid():N}";
        var subjectB = $"sub-b-{Guid.NewGuid():N}";

        var store = CreateStore();

        await store.CreateSessionAsync(new ServerSideSession
        {
            Key = $"sess-{Guid.NewGuid():N}",
            Scheme = "idsrv",
            SubjectId = subjectA,
            SessionId = $"sid-{Guid.NewGuid():N}",
            Created = DateTime.UtcNow,
            Renewed = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddHours(1),
            Ticket = "ticket-a"
        }, ct);

        await store.CreateSessionAsync(new ServerSideSession
        {
            Key = $"sess-{Guid.NewGuid():N}",
            Scheme = "idsrv",
            SubjectId = subjectB,
            SessionId = $"sid-{Guid.NewGuid():N}",
            Created = DateTime.UtcNow,
            Renewed = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddHours(1),
            Ticket = "ticket-b"
        }, ct);

        var results = await store.GetSessionsAsync(new SessionFilter { SubjectId = subjectA }, ct);

        results.Should().NotBeNull();
        results.Should().AllSatisfy(s => s.SubjectId.Should().Be(subjectA));
        results.Should().NotContain(s => s.SubjectId == subjectB);
    }

    [Fact]
    public async Task GetAndRemoveExpiredSessionsAsync_RemovesAndReturnsExpired_KeepsLive()
    {
        var ct = TestContext.Current.CancellationToken;
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var expiredKey = $"sess-{Guid.NewGuid():N}";
        var liveKey = $"sess-{Guid.NewGuid():N}";

        var store = CreateStore();

        await store.CreateSessionAsync(new ServerSideSession
        {
            Key = expiredKey,
            Scheme = "idsrv",
            SubjectId = $"sub-{Guid.NewGuid():N}",
            SessionId = $"sid-{Guid.NewGuid():N}",
            Created = DateTime.UtcNow.AddHours(-2),
            Renewed = DateTime.UtcNow.AddHours(-2),
            Expires = DateTime.UtcNow.AddMinutes(-5),
            Ticket = "expired-ticket"
        }, ct);

        await store.CreateSessionAsync(new ServerSideSession
        {
            Key = liveKey,
            Scheme = "idsrv",
            SubjectId = $"sub-{Guid.NewGuid():N}",
            SessionId = $"sid-{Guid.NewGuid():N}",
            Created = DateTime.UtcNow,
            Renewed = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddHours(1),
            Ticket = "live-ticket"
        }, ct);

        var removed = await store.GetAndRemoveExpiredSessionsAsync(10, ct);

        removed.Should().Contain(s => s.Key == expiredKey,
            "the expired session must be returned as removed");

        // Verify the expired document is physically deleted
        var systemContext = _fixture.GetSystemContext();
        var repo = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var octoSession = await repo.GetSessionAsync();
        var expiredDocs = await repo.GetRtEntitiesByTypeAsync<RtServerSideSession>(
            octoSession,
            RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtServerSideSession.SessionKey), FieldFilterOperator.Equals, expiredKey));
        expiredDocs.Items.Should().BeEmpty("expired session must be physically deleted");

        // Live session must still be retrievable
        var liveSession = await store.GetSessionAsync(liveKey, ct);
        liveSession.Should().NotBeNull("live session must not be affected by cleanup");
    }
}

/// <summary>
/// Stubs <see cref="IMultiTenancyResolverService"/> to always resolve to a fixed tenant repository.
/// Used in integration tests that run outside an HTTP request context.
/// </summary>
internal sealed class FixedTenantResolver(ITenantRepository repository) : IMultiTenancyResolverService
{
    public ITenantRepository GetTenantRepository() => repository;
    public string GetTenantId() => repository.TenantId;
}
