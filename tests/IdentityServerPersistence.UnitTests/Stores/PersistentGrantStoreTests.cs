using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Engine.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores;

public class PersistentGrantStoreTests
{
    private readonly ITenantRepository _tenantRepository;
    private readonly IMapper _mapper;
    private readonly PersistentGrantStore _sut;
    private readonly FakeOctoSession _session;

    public PersistentGrantStoreTests()
    {
        _mapper = Substitute.For<IMapper>();
        _session = new FakeOctoSession();

        _tenantRepository = Substitute.For<ITenantRepository>();
        _tenantRepository.TenantId.Returns("test-tenant");
        _tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(_session));

        var multiTenancyResolver = Substitute.For<IMultiTenancyResolverService>();
        multiTenancyResolver.GetTenantRepository().Returns(_tenantRepository);

        _sut = new PersistentGrantStore(multiTenancyResolver, _mapper);
    }

    #region StoreAsync Tests

    [Fact]
    public async Task StoreAsync_WithNewGrant_InsertsGrantAndCommits()
    {
        // Arrange
        var grant = CreatePersistedGrant("test-key", "test-subject", "test-client");

        var rtGrant = new RtPersistedGrantBuilder()
            .WithKey("test-key")
            .WithSubjectId("test-subject")
            .WithClientId("test-client")
            .Build();

        _mapper.Map<RtPersistedGrant>(grant).Returns(rtGrant);

        SetupEmptyQueryResult();

        // Act
        await _sut.StoreAsync(grant, TestContext.Current.CancellationToken);

        // Assert
        _session.TransactionStartCount.Should().Be(1);
        await _tenantRepository.Received(1).InsertOneRtEntityAsync(_session, Arg.Any<RtPersistedGrant>());
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task StoreAsync_WithExistingGrant_ReplacesGrantAndCommits()
    {
        // Arrange
        var grant = CreatePersistedGrant("existing-key", "test-subject", "test-client");

        var existingRtGrant = new RtPersistedGrantBuilder()
            .WithKey("existing-key")
            .WithSubjectId("test-subject")
            .WithClientId("test-client")
            .Build();

        var newRtGrant = new RtPersistedGrantBuilder()
            .WithKey("existing-key")
            .WithSubjectId("test-subject")
            .WithClientId("test-client")
            .WithData("updated-data")
            .Build();

        _mapper.Map<RtPersistedGrant>(grant).Returns(newRtGrant);

        SetupQueryResult(existingRtGrant);

        // Act
        await _sut.StoreAsync(grant, TestContext.Current.CancellationToken);

        // Assert
        _session.TransactionStartCount.Should().Be(1);
        await _tenantRepository.Received(1).ReplaceOneRtEntityByIdAsync(
            _session,
            existingRtGrant.RtId,
            Arg.Any<RtPersistedGrant>());
        _session.CommitCount.Should().Be(1);
    }

    #endregion

    #region GetAsync Tests

    [Fact]
    public async Task GetAsync_WithExistingKey_ReturnsGrant()
    {
        // Arrange
        var rtGrant = new RtPersistedGrantBuilder()
            .WithKey("test-key")
            .WithSubjectId("test-subject")
            .Build();

        var expectedGrant = CreatePersistedGrant("test-key", "test-subject", "test-client");

        SetupQueryResult(rtGrant);
        _mapper.Map<PersistedGrant>(rtGrant).Returns(expectedGrant);

        // Act
        var result = await _sut.GetAsync("test-key", TestContext.Current.CancellationToken);

        // Assert
        result.Should().NotBeNull();
        result!.Key.Should().Be("test-key");
        _session.TransactionStartCount.Should().Be(1);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task GetAsync_WithNonExistentKey_ReturnsNull()
    {
        // Arrange
        SetupEmptyQueryResult();
        _mapper.Map<PersistedGrant>(null).Returns((PersistedGrant?)null);

        // Act
        var result = await _sut.GetAsync("non-existent-key", TestContext.Current.CancellationToken);

        // Assert
        result.Should().BeNull();
        _session.CommitCount.Should().Be(1);
    }

    #endregion

    #region GetAllAsync Tests

    [Fact]
    public async Task GetAllAsync_WithSubjectFilter_ReturnsMatchingGrants()
    {
        // Arrange
        var rtGrant1 = new RtPersistedGrantBuilder()
            .WithKey("key1")
            .WithSubjectId("subject-1")
            .Build();
        var rtGrant2 = new RtPersistedGrantBuilder()
            .WithKey("key2")
            .WithSubjectId("subject-1")
            .Build();

        var grant1 = CreatePersistedGrant("key1", "subject-1", "client-1");
        var grant2 = CreatePersistedGrant("key2", "subject-1", "client-2");

        SetupQueryResults(rtGrant1, rtGrant2);
        _mapper.Map<PersistedGrant>(rtGrant1).Returns(grant1);
        _mapper.Map<PersistedGrant>(rtGrant2).Returns(grant2);

        var filter = new PersistedGrantFilter { SubjectId = "subject-1" };

        // Act
        var results = await _sut.GetAllAsync(filter, TestContext.Current.CancellationToken);

        // Assert
        results.Should().HaveCount(2);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task GetAllAsync_WithNoMatchingGrants_ReturnsEmptyList()
    {
        // Arrange
        SetupEmptyQueryResult();

        var filter = new PersistedGrantFilter { SubjectId = "non-existent-subject" };

        // Act
        var results = await _sut.GetAllAsync(filter, TestContext.Current.CancellationToken);

        // Assert
        results.Should().BeEmpty();
    }

    #endregion

    #region RemoveAsync Tests

    [Fact]
    public async Task RemoveAsync_WithExistingKey_DeletesGrantAndCommits()
    {
        // Arrange
        var key = "test-key";

        // Act
        await _sut.RemoveAsync(key, TestContext.Current.CancellationToken);

        // Assert
        _session.TransactionStartCount.Should().Be(1);
        // RemoveAsync uses DeleteMany (not DeleteOne) so removing a non-existent grant is a no-op
        // per Duende's IPersistedGrantStore contract — DeleteOne's exactly-one semantics would 500
        // the authorize callback when consent is submitted without a prior remembered grant.
        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtPersistedGrant>(
            _session,
            Arg.Any<FieldFilterCriteria>(),
            DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task RemoveAsync_WithNonExistentKey_CompletesWithoutError()
    {
        // Arrange - Setup repository to not throw when deleting non-existent

        // Act
        var act = () => _sut.RemoveAsync("non-existent-key");

        // Assert
        await act.Should().NotThrowAsync();
        _session.CommitCount.Should().Be(1);
    }

    #endregion

    #region RemoveAllAsync Tests

    [Fact]
    public async Task RemoveAllAsync_WithSubjectFilter_DeletesAllMatchingGrantsAndCommits()
    {
        // Arrange
        var filter = new PersistedGrantFilter { SubjectId = "test-subject" };

        // Act
        await _sut.RemoveAllAsync(filter, TestContext.Current.CancellationToken);

        // Assert
        _session.TransactionStartCount.Should().Be(1);
        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtPersistedGrant>(
            _session,
            Arg.Any<FieldFilterCriteria>(),
            DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task RemoveAllAsync_WithNoMatchingGrants_CompletesWithoutError()
    {
        // Arrange
        var filter = new PersistedGrantFilter { SubjectId = "non-existent-subject" };

        // Act
        var act = () => _sut.RemoveAllAsync(filter);

        // Assert
        await act.Should().NotThrowAsync();
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task RemoveAllAsync_WithSubjectAndClientFilter_DeletesOnlyMatchingGrants()
    {
        // Arrange
        var filter = new PersistedGrantFilter
        {
            SubjectId = "test-subject",
            ClientId = "test-client"
        };

        // Act
        await _sut.RemoveAllAsync(filter, TestContext.Current.CancellationToken);

        // Assert
        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtPersistedGrant>(
            _session,
            Arg.Is<FieldFilterCriteria>(c => c != null),
            DeleteOptions.Erase);
    }

    [Fact]
    public async Task RemoveAllAsync_WithSubjectAndTypeFilter_DeletesOnlyMatchingType()
    {
        // Arrange
        var filter = new PersistedGrantFilter
        {
            SubjectId = "test-subject",
            Type = "refresh_token"
        };

        // Act
        await _sut.RemoveAllAsync(filter, TestContext.Current.CancellationToken);

        // Assert
        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtPersistedGrant>(
            _session,
            Arg.Any<FieldFilterCriteria>(),
            DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task RemoveAllAsync_WithSessionIdFilter_DeletesMatchingGrants()
    {
        // Arrange
        var filter = new PersistedGrantFilter
        {
            SubjectId = "test-subject",
            SessionId = "test-session"
        };

        // Act
        await _sut.RemoveAllAsync(filter, TestContext.Current.CancellationToken);

        // Assert
        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtPersistedGrant>(
            _session,
            Arg.Any<FieldFilterCriteria>(),
            DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task RemoveAllAsync_WithAllFilters_DeletesMatchingGrants()
    {
        // Arrange
        var filter = new PersistedGrantFilter
        {
            SubjectId = "test-subject",
            ClientId = "test-client",
            SessionId = "test-session",
            Type = "refresh_token"
        };

        // Act
        await _sut.RemoveAllAsync(filter, TestContext.Current.CancellationToken);

        // Assert
        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtPersistedGrant>(
            _session,
            Arg.Any<FieldFilterCriteria>(),
            DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    #endregion

    #region RemoveAllAsync (Overload) Tests

    [Fact]
    public async Task RemoveAllAsync_WithSubjectClientAndType_DeletesMatchingGrants()
    {
        // Arrange
        var subjectId = "test-subject";
        var clientId = "test-client";
        var type = "refresh_token";

        // Act
        await _sut.RemoveAllAsync(subjectId, clientId, type);

        // Assert
        _session.TransactionStartCount.Should().Be(1);
        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtPersistedGrant>(
            _session,
            Arg.Any<FieldFilterCriteria>(),
            DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    #endregion

    #region StoreAsync (RtPersistedGrant) Tests

    [Fact]
    public async Task StoreAsync_RtGrant_WithNewGrant_InsertsGrant()
    {
        // Arrange
        var rtGrant = new RtPersistedGrantBuilder()
            .WithKey("new-key")
            .WithSubjectId("test-subject")
            .Build();

        SetupEmptyQueryResult();

        // Act
        await _sut.StoreAsync(rtGrant);

        // Assert
        await _tenantRepository.Received(1).InsertOneRtEntityAsync(_session, rtGrant);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task StoreAsync_RtGrant_WithExistingGrant_ReplacesGrant()
    {
        // Arrange
        var existingGrant = new RtPersistedGrantBuilder()
            .WithKey("existing-key")
            .Build();

        var newGrant = new RtPersistedGrantBuilder()
            .WithKey("existing-key")
            .WithData("updated-data")
            .Build();

        SetupQueryResult(existingGrant);

        // Act
        await _sut.StoreAsync(newGrant);

        // Assert
        await _tenantRepository.Received(1).ReplaceOneRtEntityByIdAsync(
            _session,
            existingGrant.RtId,
            newGrant);
        _session.CommitCount.Should().Be(1);
    }

    #endregion

    #region RemoveExpiredGrantsAsync Tests

    [Fact]
    public async Task RemoveExpiredGrantsAsync_WithExpiredGrants_RemovesThemInBatches()
    {
        // Arrange: First call returns a batch, second call returns empty
        var expiredGrant = new RtPersistedGrantBuilder()
            .WithKey("expired-key")
            .Expired()
            .Build();

        var callCount = 0;
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtEntityQueryOptions>(),
                Arg.Any<int>(),
                Arg.Any<int>())
            .Returns(_ =>
            {
                callCount++;
                if (callCount == 1)
                {
                    return Task.FromResult<IResultSet<RtPersistedGrant>>(
                        new ResultSet<RtPersistedGrant>([expiredGrant], 1, null, null));
                }
                return Task.FromResult<IResultSet<RtPersistedGrant>>(
                    new ResultSet<RtPersistedGrant>([], 0, null, null));
            });

        // Act
        await _sut.RemoveExpiredGrantsAsync();

        // Assert
        await _tenantRepository.Received(1).DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(
            Arg.Any<IOctoSession>(), expiredGrant.RtId, DeleteOptions.Erase);
    }

    [Fact]
    public async Task RemoveExpiredGrantsAsync_WithConcurrencyFailureOnAllDeletes_TerminatesLoop()
    {
        // Arrange: Return a batch of expired grants, but all deletes fail with concurrency errors
        var expiredGrant1 = new RtPersistedGrantBuilder().WithKey("expired-1").Expired().Build();
        var expiredGrant2 = new RtPersistedGrantBuilder().WithKey("expired-2").Expired().Build();

        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtEntityQueryOptions>(),
                Arg.Any<int>(),
                Arg.Any<int>())
            .Returns(Task.FromResult<IResultSet<RtPersistedGrant>>(
                new ResultSet<RtPersistedGrant>([expiredGrant1, expiredGrant2], 2, null, null)));

        _tenantRepository
            .DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(), Arg.Any<OctoObjectId>(), Arg.Any<DeleteOptions>())
            .Returns<Task>(_ => throw OperationFailedException.DatabaseOperationFailed(
                "DeleteOne", new Exception("Concurrency conflict")));

        // Act - should terminate without infinite loop
        await _sut.RemoveExpiredGrantsAsync();

        // Assert: The loop should have broken after the first batch where no deletes succeeded.
        // It should NOT have re-queried endlessly.
        await _tenantRepository.Received(2).DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(
            Arg.Any<IOctoSession>(), Arg.Any<OctoObjectId>(), DeleteOptions.Erase);
    }

    [Fact]
    public async Task RemoveExpiredGrantsAsync_WithPartialConcurrencyFailure_ContinuesProcessing()
    {
        // Arrange: Return a full batch (>= TokenCleanupBatchSize) where one delete succeeds
        // and one fails, then an empty batch on second query
        var grants = Enumerable.Range(0, 50).Select(i =>
            new RtPersistedGrantBuilder().WithKey($"grant-{i}").Expired().Build()).ToList();

        var callCount = 0;
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtEntityQueryOptions>(),
                Arg.Any<int>(),
                Arg.Any<int>())
            .Returns(_ =>
            {
                callCount++;
                if (callCount == 1)
                {
                    return Task.FromResult<IResultSet<RtPersistedGrant>>(
                        new ResultSet<RtPersistedGrant>(grants, grants.Count, null, null));
                }
                return Task.FromResult<IResultSet<RtPersistedGrant>>(
                    new ResultSet<RtPersistedGrant>([], 0, null, null));
            });

        // First grant delete succeeds, all others throw concurrency error
        _tenantRepository
            .DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(), grants[0].RtId, Arg.Any<DeleteOptions>())
            .Returns(Task.CompletedTask);
        _tenantRepository
            .DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(),
                Arg.Is<OctoObjectId>(id => id != grants[0].RtId),
                Arg.Any<DeleteOptions>())
            .Returns<Task>(_ => throw OperationFailedException.DatabaseOperationFailed(
                "DeleteOne", new Exception("Concurrency conflict")));

        // Act
        await _sut.RemoveExpiredGrantsAsync();

        // Assert: Should have continued (deletedCount > 0) and queried for the next batch
        callCount.Should().Be(2);
    }

    #endregion

    #region Helper Methods

    private static PersistedGrant CreatePersistedGrant(string key, string subjectId, string clientId)
    {
        return new PersistedGrant
        {
            Key = key,
            SubjectId = subjectId,
            ClientId = clientId,
            Type = "refresh_token",
            CreationTime = DateTime.UtcNow,
            Expiration = DateTime.UtcNow.AddDays(30),
            Data = "{}"
        };
    }

    private void SetupEmptyQueryResult()
    {
        var emptyResult = new ResultSet<RtPersistedGrant>([], 0, null, null);
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtPersistedGrant>>(emptyResult));
    }

    private void SetupQueryResult(RtPersistedGrant grant)
    {
        var result = new ResultSet<RtPersistedGrant>([grant], 1, null, null);
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtPersistedGrant>>(result));
    }

    private void SetupQueryResults(params RtPersistedGrant[] grants)
    {
        var result = new ResultSet<RtPersistedGrant>(grants.ToList(), grants.Length, null, null);
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtPersistedGrant>(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtPersistedGrant>>(result));
    }

    #endregion
}
