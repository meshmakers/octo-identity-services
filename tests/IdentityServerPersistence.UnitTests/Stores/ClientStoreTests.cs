using AutoMapper;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores;

public class ClientStoreTests
{
    private readonly ITenantRepository _tenantRepository;
    private readonly IMapper _mapper;
    private readonly IMultiTenancyResolverService _multiTenancyResolver;
    private readonly ClientStore _sut;
    private readonly FakeOctoSession _session;

    public ClientStoreTests()
    {
        _multiTenancyResolver = Substitute.For<IMultiTenancyResolverService>();
        _mapper = Substitute.For<IMapper>();
        _session = new FakeOctoSession();

        _tenantRepository = Substitute.For<ITenantRepository>();
        _tenantRepository.TenantId.Returns("test-tenant");
        _tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(_session));

        _multiTenancyResolver.GetTenantRepository().Returns(_tenantRepository);

        _sut = new ClientStore(_multiTenancyResolver, _mapper);
    }

    [Fact]
    public async Task CreateAsync_InsertsClientAndCommits()
    {
        // Arrange
        var client = new RtClientBuilder()
            .WithClientId("test-client")
            .Build();

        // Act
        await _sut.CreateAsync(client);

        // Assert
        _session.TransactionStartCount.Should().Be(1);
        await _tenantRepository.Received(1).InsertOneRtEntityAsync(_session, client);
        _session.CommitCount.Should().Be(1);
    }

    [Fact]
    public void TenantId_ReturnsRepositoryTenantId()
    {
        // Act & Assert
        _sut.TenantId.Should().Be("test-tenant");
    }

    [Fact]
    public async Task CreateAsync_WithAllProperties_InsertsCorrectly()
    {
        // Arrange
        var client = new RtClientBuilder()
            .WithClientId("full-client")
            .WithClientName("Full Client")
            .WithDescription("A fully configured client")
            .WithGrantTypes("authorization_code", "refresh_token")
            .WithScopes("openid", "profile", "api")
            .WithRedirectUris("https://app.example.com/callback")
            .WithPostLogoutRedirectUris("https://app.example.com/logout")
            .WithCorsOrigins("https://app.example.com")
            .RequireClientSecret(true)
            .RequirePkce(true)
            .WithAccessTokenLifetime(3600)
            .Build();

        // Act
        await _sut.CreateAsync(client);

        // Assert
        await _tenantRepository.Received(1).InsertOneRtEntityAsync(
            _session,
            Arg.Is<RtClient>(c =>
                c.ClientId == "full-client" &&
                c.ClientName == "Full Client" &&
                c.RequireClientSecret == true &&
                c.RequirePkce == true &&
                c.AccessTokenLifetime == 3600));
    }

    [Fact]
    public void TenantRepository_ResolvesLazily_NotInConstructor()
    {
        // Arrange — set up resolver to return different repos on successive calls
        var resolver = Substitute.For<IMultiTenancyResolverService>();
        var mapper = Substitute.For<IMapper>();

        // Constructor should NOT call GetTenantRepository
        var store = new ClientStore(resolver, mapper);
        resolver.DidNotReceive().GetTenantRepository();

        // Act — accessing TenantId triggers lazy resolution
        var repo = Substitute.For<ITenantRepository>();
        repo.TenantId.Returns("lazy-tenant");
        resolver.GetTenantRepository().Returns(repo);

        var tenantId = store.TenantId;

        // Assert
        tenantId.Should().Be("lazy-tenant");
        resolver.Received(1).GetTenantRepository();
    }

    [Fact]
    public async Task CreateAsync_UsesCurrentTenantRepository_NotCachedFromConstructor()
    {
        // Arrange — simulate tenant switching between constructor and method call
        var resolver = Substitute.For<IMultiTenancyResolverService>();
        var mapper = Substitute.For<IMapper>();

        var tenantARepo = Substitute.For<ITenantRepository>();
        tenantARepo.TenantId.Returns("tenant-a");
        var sessionA = new FakeOctoSession();
        tenantARepo.GetSessionAsync().Returns(Task.FromResult<IOctoSession>(sessionA));

        // Resolver returns tenant-a at method call time
        resolver.GetTenantRepository().Returns(tenantARepo);

        var store = new ClientStore(resolver, mapper);
        var client = new RtClientBuilder().WithClientId("test").Build();

        // Act
        await store.CreateAsync(client);

        // Assert — should have used tenant-a repo
        await tenantARepo.Received(1).InsertOneRtEntityAsync(sessionA, client);
        store.TenantId.Should().Be("tenant-a");
    }
}
