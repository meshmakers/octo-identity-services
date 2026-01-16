using System.Net;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Xunit;

namespace IdentityServices.IntegrationTests.Api;

/// <summary>
/// HTTP-based integration tests for health endpoints.
///
/// Note: These tests require the full ASP.NET Core web host to be running with a properly
/// initialized Octo system tenant. The WebApplicationFactory needs the system database
/// to be set up before the web host starts, which requires additional infrastructure
/// that is not yet implemented.
///
/// For now, use the fixture-based tests in IdentityServices.IntegrationTests.Persistence
/// which test the system initialization directly.
/// </summary>
public class HealthCheckTests : IntegrationTestBase
{
    public HealthCheckTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact(Skip = "WebApplicationFactory tests require system tenant initialization before web host starts")]
    public async Task HealthEndpoint_ReturnsOk()
    {
        // Act
        var response = await Client.GetAsync("/health");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact(Skip = "WebApplicationFactory tests require system tenant initialization before web host starts")]
    public async Task HomeEndpoint_ReturnsSuccessStatusCode()
    {
        // Act
        var response = await Client.GetAsync("/");

        // Assert
        response.IsSuccessStatusCode.Should().BeTrue();
    }
}
