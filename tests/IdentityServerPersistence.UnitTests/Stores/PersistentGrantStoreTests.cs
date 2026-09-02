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
    private readonly PersistentGrantStore _sut;
    private readonly FakeOctoSession _session;

    public PersistentGrantStoreTests()
    {
        _session = new FakeOctoSession();

        _tenantRepository = Substitute.For<ITenantRepository>();
        _tenantRepository.TenantId.Returns("test-tenant");
        _tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(_session));

        var multiTenancyResolver = Substitute.For<IMultiTenancyResolverService>();
        multiTenancyResolver.GetTenantRepository().Returns(_tenantRepository);

        _sut = new PersistentGrantStore(multiTenancyResolver);
    }

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
