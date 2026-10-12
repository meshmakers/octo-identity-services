using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.Authentication.Secrets;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace Authentication.UnitTests.DynamicAuth;

/// <summary>
/// Tests for Dynamic Authentication Scheme Service functionality.
/// Note: DynamicAuthSchemeService is internal, so these tests verify the public interfaces
/// and behavior through the IOctoIdentityProviderStore.
/// </summary>
public class DynamicAuthSchemeServiceTests
{
    private readonly IOctoIdentityProviderStore _identityProviderStore;
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    public DynamicAuthSchemeServiceTests()
    {
        _identityProviderStore = Substitute.For<IOctoIdentityProviderStore>();
        _schemeProvider = Substitute.For<IAuthenticationSchemeProvider>();
    }

    [Fact]
    public async Task GetAllAsync_ReturnsConfiguredProviders()
    {
        // Arrange
        var googleProvider = new RtGoogleIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = "Google",
            IsEnabled = true,
            ClientId = "google-client-id",
            ClientSecret = RtSecretValue.Pending("google-secret")
        };

        _identityProviderStore.GetAllAsync().Returns(new RtIdentityProvider[] { googleProvider });

        // Act
        var providers = await _identityProviderStore.GetAllAsync();

        // Assert
        providers.Should().HaveCount(1);
        providers.First().Should().BeOfType<RtGoogleIdentityProvider>();
    }

    [Fact]
    public async Task GetByNameAsync_WhenProviderExists_ReturnsProvider()
    {
        // Arrange
        var microsoftProvider = new RtMicrosoftIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = "Microsoft",
            IsEnabled = true,
            ClientId = "microsoft-client-id",
            ClientSecret = RtSecretValue.Pending("microsoft-secret")
        };

        _identityProviderStore.GetByNameAsync("Microsoft").Returns(microsoftProvider);

        // Act
        var provider = await _identityProviderStore.GetByNameAsync("Microsoft");

        // Assert
        provider.Should().NotBeNull();
        provider!.Name.Should().Be("Microsoft");
        provider.Should().BeOfType<RtMicrosoftIdentityProvider>();
    }

    [Fact]
    public async Task GetByNameAsync_WhenProviderNotExists_ReturnsNull()
    {
        // Arrange
        _identityProviderStore.GetByNameAsync("NonExistent").Returns((RtIdentityProvider?)null);

        // Act
        var provider = await _identityProviderStore.GetByNameAsync("NonExistent");

        // Assert
        provider.Should().BeNull();
    }

    [Fact]
    public async Task GetAllAsync_WithMultipleProviderTypes_ReturnsAllProviders()
    {
        // Arrange
        var providers = new RtIdentityProvider[]
        {
            new RtGoogleIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = "Google",
                IsEnabled = true
            },
            new RtMicrosoftIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = "Microsoft",
                IsEnabled = true
            },
            new RtAzureEntraIdIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = "AzureEntraId",
                IsEnabled = false
            }
        };

        _identityProviderStore.GetAllAsync().Returns(providers);

        // Act
        var result = await _identityProviderStore.GetAllAsync();

        // Assert
        result.Should().HaveCount(3);
        result.Where(p => p.IsEnabled).Should().HaveCount(2);
    }

    [Fact]
    public async Task SchemeProvider_CanAddAndRemoveSchemes()
    {
        // Arrange
        var scheme = new AuthenticationScheme("TestScheme", "Test Scheme", typeof(GoogleHandler));

        // Act
        _schemeProvider.AddScheme(scheme);
        _schemeProvider.RemoveScheme("TestScheme");

        // Assert
        _schemeProvider.Received(1).AddScheme(scheme);
        _schemeProvider.Received(1).RemoveScheme("TestScheme");
    }

    // Regression for ADO #4199 Bug 3: ConfigureAsync must lower-case the tenant id so the
    // registered scheme prefix matches the lower-cased lookup in AuthApiController (the URL
    // path segment can be PascalCase when the system tenant config uses PascalCase, e.g.
    // /OctoSystem/api/auth/external-providers). Without normalization the cleanup pass for a
    // re-register would miss the lower-cased scheme and the duplicate would never be removed.
    [Fact]
    public async Task ConfigureAsync_PascalCaseTenantId_CleansUpLowercaseSchemes()
    {
        var systemContext = Substitute.For<ISystemContext>();
        var factory = Substitute.For<IAuthSchemeCreatorFactory>();

        var existing = new AuthenticationScheme("octosystem:meshmakers", "meshmakers", typeof(GoogleHandler));
        var unrelated = new AuthenticationScheme("othertenant:foo", "foo", typeof(GoogleHandler));
        _schemeProvider.GetAllSchemesAsync()
            .Returns(Task.FromResult<IEnumerable<AuthenticationScheme>>(new[] { existing, unrelated }));

        var tenantRepo = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        tenantRepo.GetSessionAsync().Returns(session);
        var emptyResult = Substitute.For<IResultSet<RtIdentityProvider>>();
        emptyResult.Items.Returns(Array.Empty<RtIdentityProvider>());
        tenantRepo.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(emptyResult);
        systemContext.FindTenantRepositoryAsync("octosystem").Returns(tenantRepo);

        var sut = new DynamicAuthSchemeService(systemContext, _schemeProvider, factory,
            Substitute.For<IIdentityProviderSecretReader>(), NullLogger<DynamicAuthSchemeService>.Instance);

        await sut.ConfigureAsync("OctoSystem");

        _schemeProvider.Received(1).RemoveScheme("octosystem:meshmakers");
        _schemeProvider.DidNotReceive().RemoveScheme("othertenant:foo");
        await systemContext.Received(1).FindTenantRepositoryAsync("octosystem");
    }

    // AB#5540 / decision r2-2: a provider whose client secret cannot be revealed is skipped; the
    // tenant's other providers are still registered (an unexpected exception type would abort the loop).
    [Fact]
    public async Task ConfigureAsync_UnrevealableClientSecret_SkipsOnlyThatProvider()
    {
        var systemContext = Substitute.For<ISystemContext>();
        var factory = Substitute.For<IAuthSchemeCreatorFactory>();
        _schemeProvider.GetAllSchemesAsync()
            .Returns(Task.FromResult<IEnumerable<AuthenticationScheme>>(Array.Empty<AuthenticationScheme>()));

        var broken = new RtGoogleIdentityProvider
            { RtId = OctoObjectId.GenerateNewId(), Name = "Broken", IsEnabled = true, ClientId = "a" };
        var working = new RtGoogleIdentityProvider
            { RtId = OctoObjectId.GenerateNewId(), Name = "Working", IsEnabled = true, ClientId = "b" };

        var tenantRepo = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        tenantRepo.GetSessionAsync().Returns(session);
        var result = Substitute.For<IResultSet<RtIdentityProvider>>();
        result.Items.Returns(new RtIdentityProvider[] { broken, working });
        tenantRepo.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(result);
        systemContext.FindTenantRepositoryAsync("acme").Returns(tenantRepo);

        var creator = Substitute.For<IAuthSchemeCreator<RtGoogleIdentityProvider>>();
        creator.Create(broken, Arg.Any<string?>(), Arg.Any<string?>())
            .Returns(_ => throw new SecretEnvelopeNotAllowedException("acme", "System.Identity/GoogleIdentityProvider",
                "ClientSecret"));
        var workingScheme = new AuthenticationScheme("acme:Working", "Working", typeof(GoogleHandler));
        creator.Create(working, Arg.Any<string?>(), Arg.Any<string?>()).Returns(workingScheme);
        factory.GetCreator<RtGoogleIdentityProvider>().Returns(creator);

        var sut = new DynamicAuthSchemeService(systemContext, _schemeProvider, factory,
            Substitute.For<IIdentityProviderSecretReader>(), NullLogger<DynamicAuthSchemeService>.Instance);

        await sut.ConfigureAsync("acme");

        _schemeProvider.Received(1).AddScheme(workingScheme);
        _schemeProvider.Received(1).AddScheme(Arg.Any<AuthenticationScheme>());
    }
}
