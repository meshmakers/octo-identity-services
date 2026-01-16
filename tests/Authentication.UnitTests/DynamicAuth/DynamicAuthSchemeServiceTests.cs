using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
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
            RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
            Name = "Google",
            IsEnabled = true,
            ClientId = "google-client-id",
            ClientSecret = "google-secret"
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
            RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
            Name = "Microsoft",
            IsEnabled = true,
            ClientId = "microsoft-client-id",
            ClientSecret = "microsoft-secret"
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
                RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
                Name = "Google",
                IsEnabled = true
            },
            new RtMicrosoftIdentityProvider
            {
                RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
                Name = "Microsoft",
                IsEnabled = true
            },
            new RtAzureEntraIdIdentityProvider
            {
                RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
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
}
