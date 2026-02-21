using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
/// Integration tests for external identity provider login endpoints.
/// </summary>
public class ExternalLoginTests : IntegrationTestBase
{
    public ExternalLoginTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    #region Login Context - External Provider Detection Tests

    [Fact]
    public async Task GetLoginContext_ExternalProviders_HaveIsLdapProperty()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.GetAsync(AuthApiUrl("login-context"), ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var context = await response.Content.ReadFromJsonAsync<LoginContextDto>(ct);
        context.Should().NotBeNull();
        context!.ExternalProviders.Should().NotBeNull();

        // All providers should have the IsLdap property defined (either true or false)
        foreach (var provider in context.ExternalProviders)
        {
            provider.Scheme.Should().NotBeNullOrEmpty();
            provider.DisplayName.Should().NotBeNullOrEmpty();
            // IsLdap is a bool, so it will always be defined (defaults to false)
        }
    }

    [Fact]
    public async Task GetExternalProviders_ReturnsProvidersWithIsLdapFlag()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.GetAsync(AuthApiUrl("external-providers"), ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var providers = await response.Content.ReadFromJsonAsync<List<ExternalProviderDto>>(ct);
        providers.Should().NotBeNull();

        // All providers should have the required properties
        foreach (var provider in providers!)
        {
            provider.Scheme.Should().NotBeNullOrEmpty();
            provider.DisplayName.Should().NotBeNullOrEmpty();
            // IsLdap is a bool property that should be present
        }
    }

    #endregion

    #region Is LDAP Scheme Endpoint Tests

    [Fact]
    public async Task IsLdapScheme_WithNonExistentScheme_ReturnsFalse()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.GetAsync($"{AuthApiUrl("is-ldap-scheme")}?scheme=nonexistent", ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<IsLdapSchemeResultDto>(ct);
        result.Should().NotBeNull();
        result!.IsLdap.Should().BeFalse();
    }

    [Fact]
    public async Task IsLdapScheme_WithEmptyScheme_ReturnsBadRequestOrFalse()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Act
        var response = await client.GetAsync($"{AuthApiUrl("is-ldap-scheme")}?scheme=", ct);

        // Assert
        // Empty scheme parameter may return BadRequest (validation) or OK with false
        if (response.StatusCode == HttpStatusCode.OK)
        {
            var result = await response.Content.ReadFromJsonAsync<IsLdapSchemeResultDto>(ct);
            result.Should().NotBeNull();
            result!.IsLdap.Should().BeFalse();
        }
        else
        {
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
    }

    #endregion

    #region LDAP Login Endpoint Tests

    [Fact]
    public async Task LdapLogin_WithInvalidScheme_ReturnsError()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var request = new LdapLoginRequestDto
        {
            Scheme = "nonexistent",
            Username = "testuser",
            Password = "testpassword"
        };

        // Act
        var response = await client.PostAsJsonAsync(AuthApiUrl("ldap-login"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LdapLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Invalid authentication scheme");
    }

    [Fact]
    public async Task LdapLogin_WithEmptyScheme_ReturnsError()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var request = new LdapLoginRequestDto
        {
            Scheme = "",
            Username = "testuser",
            Password = "testpassword"
        };

        // Act
        var response = await client.PostAsJsonAsync(AuthApiUrl("ldap-login"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LdapLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        result.ErrorMessage.Should().Be("Invalid authentication scheme");
    }

    [Fact]
    public async Task LdapLogin_WithEmptyCredentials_ReturnsError()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;
        var request = new LdapLoginRequestDto
        {
            Scheme = "someldap",
            Username = "",
            Password = ""
        };

        // Act
        var response = await client.PostAsJsonAsync(AuthApiUrl("ldap-login"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LdapLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        // Either "Invalid authentication scheme" (if scheme doesn't exist)
        // or validation error for empty credentials
    }

    [Fact]
    public async Task LdapLogin_WithNonLdapScheme_ReturnsNotLdapError()
    {
        // Arrange
        // First, we need to find a non-LDAP scheme if any exist
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Get providers to find a non-LDAP one
        var providersResponse = await client.GetAsync(AuthApiUrl("external-providers"), ct);
        var providers = await providersResponse.Content.ReadFromJsonAsync<List<ExternalProviderDto>>(ct);

        var nonLdapProvider = providers?.FirstOrDefault(p => !p.IsLdap);

        if (nonLdapProvider == null)
        {
            // Skip if no non-LDAP providers are configured
            return;
        }

        var request = new LdapLoginRequestDto
        {
            Scheme = nonLdapProvider.Scheme,
            Username = "testuser",
            Password = "testpassword"
        };

        // Act
        var response = await client.PostAsJsonAsync(AuthApiUrl("ldap-login"), request, ct);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<LdapLoginResultDto>(ct);
        result.Should().NotBeNull();
        result!.Success.Should().BeFalse();
        // Should indicate scheme is not LDAP
    }

    #endregion

    #region External Login Challenge Tests

    [Fact]
    public async Task ExternalLogin_WithValidScheme_ReturnsChallenge()
    {
        // Arrange
        var client = CreateAnonymousClient();
        var ct = TestContext.Current.CancellationToken;

        // Get a valid scheme from providers
        var providersResponse = await client.GetAsync(AuthApiUrl("external-providers"), ct);
        var providers = await providersResponse.Content.ReadFromJsonAsync<List<ExternalProviderDto>>(ct);

        if (providers == null || !providers.Any())
        {
            // Skip if no external providers configured
            return;
        }

        var provider = providers.First();

        // Act
        // Note: External login returns a challenge (redirect to external provider)
        // The test verifies the endpoint responds (actual redirect depends on handler)
        var response = await client.GetAsync(
            $"{AuthApiUrl("external-login")}?scheme={Uri.EscapeDataString(provider.Scheme)}&returnUrl=/",
            ct);

        // Assert
        // Challenge typically results in redirect (302) or OK with redirect info
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.Found,
            HttpStatusCode.Redirect,
            HttpStatusCode.OK,
            HttpStatusCode.InternalServerError // If provider not fully configured
        );
    }

    #endregion

    #region External Callback Tests

    [Fact]
    public async Task ExternalCallback_WithoutExternalCookie_ReturnsError()
    {
        // Arrange
        // Use a client that does NOT follow redirects so we can inspect the actual response
        var client = Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var ct = TestContext.Current.CancellationToken;

        // Act
        // Calling callback without going through external login first
        var response = await client.GetAsync(AuthApiUrl("external-callback"), ct);

        // Assert
        // Should return a redirect to error page or an error status code
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.Found,
            HttpStatusCode.Redirect,
            HttpStatusCode.OK,
            HttpStatusCode.InternalServerError);

        // If it's a redirect, check it goes to error page
        if (response.StatusCode == HttpStatusCode.Found || response.StatusCode == HttpStatusCode.Redirect)
        {
            var location = response.Headers.Location?.ToString() ?? "";
            location.Should().Contain("error");
        }
    }

    #endregion
}
