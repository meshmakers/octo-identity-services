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
}
