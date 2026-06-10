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
using Meshmakers.Octo.Services.Infrastructure.Services;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores;

public class ServerSideSessionStoreTests
{
    private readonly ITenantRepository _tenantRepository;
    private readonly IMapper _mapper;
    private readonly ISystemContext _systemContext;
    private readonly ServerSideSessionStore _sut;
    private readonly FakeOctoSession _session;

    public ServerSideSessionStoreTests()
    {
        var multiTenancyResolver = Substitute.For<IMultiTenancyResolverService>();
        _mapper = Substitute.For<IMapper>();
        _systemContext = Substitute.For<ISystemContext>();
        _session = new FakeOctoSession();

        _tenantRepository = Substitute.For<ITenantRepository>();
        _tenantRepository.TenantId.Returns("test-tenant");
        _tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(_session));

        multiTenancyResolver.GetTenantRepository().Returns(_tenantRepository);

        _sut = new ServerSideSessionStore(multiTenancyResolver, _systemContext, _mapper);
    }

    private void SetupSessionLookup(params RtServerSideSession[] sessions)
    {
        var resultSet = Substitute.For<IResultSet<RtServerSideSession>>();
        resultSet.Items.Returns(sessions);
        _tenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(
                _session, Arg.Any<RtEntityQueryOptions>())
            .Returns(resultSet);
    }

    [Fact]
    public async Task GetSessionAsync_UnknownKey_ReturnsNull()
    {
        SetupSessionLookup();

        var result = await _sut.GetSessionAsync("missing-key", CancellationToken.None);

        result.Should().BeNull();
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSessionAsync_ExpiredSession_ReturnsNull_WithoutMapping()
    {
        // Expired-but-not-yet-cleaned sessions must NOT authenticate (cleanup runs periodically).
        SetupSessionLookup(new RtServerSideSession
        {
            RtId = OctoObjectId.GenerateNewId(),
            SessionKey = "expired-key",
            ExpirationDateTime = DateTime.UtcNow.AddMinutes(-5)
        });

        var result = await _sut.GetSessionAsync("expired-key", CancellationToken.None);

        result.Should().BeNull();
        _mapper.DidNotReceiveWithAnyArgs().Map<ServerSideSession>(default(RtServerSideSession));
    }

    [Fact]
    public async Task GetSessionAsync_LiveSession_MapsAndReturns()
    {
        var rtSession = new RtServerSideSession
        {
            RtId = OctoObjectId.GenerateNewId(),
            SessionKey = "live-key",
            ExpirationDateTime = DateTime.UtcNow.AddHours(1)
        };
        SetupSessionLookup(rtSession);
        var mapped = new ServerSideSession { Key = "live-key" };
        _mapper.Map<ServerSideSession>(rtSession).Returns(mapped);

        var result = await _sut.GetSessionAsync("live-key", CancellationToken.None);

        result.Should().BeSameAs(mapped);
    }

    [Fact]
    public async Task CreateSessionAsync_InsertsAndCommits()
    {
        var duendeSession = new ServerSideSession { Key = "new-key" };
        var rtSession = new RtServerSideSession { SessionKey = "new-key" };
        _mapper.Map<RtServerSideSession>(duendeSession).Returns(rtSession);

        await _sut.CreateSessionAsync(duendeSession, CancellationToken.None);

        _session.TransactionStartCount.Should().Be(1);
        await _tenantRepository.Received(1).InsertOneRtEntityAsync(_session, rtSession);
        _session.CommitCount.Should().Be(1);
        rtSession.RtId.Should().NotBe(default(OctoObjectId));
    }

    [Fact]
    public async Task UpdateSessionAsync_ExistingSession_ReplacesByRtId()
    {
        var existingRtId = OctoObjectId.GenerateNewId();
        SetupSessionLookup(new RtServerSideSession { RtId = existingRtId, SessionKey = "renew-key" });
        var duendeSession = new ServerSideSession { Key = "renew-key" };
        var replacement = new RtServerSideSession { SessionKey = "renew-key" };
        _mapper.Map<RtServerSideSession>(duendeSession).Returns(replacement);

        await _sut.UpdateSessionAsync(duendeSession, CancellationToken.None);

        await _tenantRepository.Received(1)
            .ReplaceOneRtEntityByIdAsync(_session, existingRtId, replacement);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task DeleteSessionAsync_DeletesByKeyAndCommits()
    {
        await _sut.DeleteSessionAsync("dead-key", CancellationToken.None);

        await _tenantRepository.Received(1).DeleteOneRtEntityAsync<RtServerSideSession>(
            _session, Arg.Any<FieldFilterCriteria>(), DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public async Task DeleteSessionsAsync_BySubjectId_DeletesManyAndCommits()
    {
        await _sut.DeleteSessionsAsync(
            new SessionFilter { SubjectId = "subject-1" }, CancellationToken.None);

        await _tenantRepository.Received(1).DeleteManyRtEntitiesAsync<RtServerSideSession>(
            _session, Arg.Any<FieldFilterCriteria>(), DeleteOptions.Erase);
        _session.CommitCount.Should().Be(1);
    }
}
