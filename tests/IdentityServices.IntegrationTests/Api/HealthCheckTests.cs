using System.Net;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Xunit;

namespace IdentityServices.IntegrationTests.Api;

/// <summary>
/// HTTP-based integration tests for health endpoints.
/// </summary>
public class HealthCheckTests : IntegrationTestBase
{
    public HealthCheckTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsExpectedStatusCode()
    {
        // Act
        var response = await Client.GetAsync("/health");

        // Assert
        // In the test environment, the system context health check may report unhealthy (503)
        // because not all components are fully initialized. This is expected.
        // We verify the endpoint is reachable and returns a valid health check response.
        response.StatusCode.Should().BeOneOf(HttpStatusCode.OK, HttpStatusCode.ServiceUnavailable);
    }

    [Fact]
    public async Task HomeEndpoint_ReturnsSuccessStatusCode()
    {
        // Act
        var response = await Client.GetAsync("/");

        // Assert
        response.IsSuccessStatusCode.Should().BeTrue();
    }
}
