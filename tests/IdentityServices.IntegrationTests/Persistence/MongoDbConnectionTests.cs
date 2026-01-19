using FluentAssertions;
using IdentityServices.IntegrationTests.Fixtures;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// Integration tests verifying MongoDB connection and system tenant setup.
/// </summary>
[Collection("Sequential")]
public class MongoDbConnectionTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public MongoDbConnectionTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task GetConnectionString_WhenContainerStarted_ReturnsValidConnectionString()
    {
        // Arrange & Act
        await _fixture.InitializeAsync();

        var connectionString = _fixture.GetConnectionString();

        // Assert
        connectionString.Should().NotBeNullOrEmpty();
        connectionString.Should().Contain("mongodb://");
        // Host can be 127.0.0.1 (local) or 172.17.0.1 (DinD bridge gateway)
        connectionString.Should().MatchRegex(@"(127\.0\.0\.1|172\.17\.0\.1)");
    }

    [Fact]
    public async Task SystemTenant_WhenInitialized_Exists()
    {
        // Arrange & Act
        await _fixture.InitializeAsync();

        var systemContext = _fixture.GetSystemContext();
        var exists = await systemContext.IsSystemTenantExistingAsync();

        // Assert
        exists.Should().BeTrue();
    }

    [Fact]
    public async Task TestTenant_WhenInitialized_CanBeRetrieved()
    {
        // Arrange & Act
        await _fixture.InitializeAsync();

        var tenantContext = await _fixture.GetTestTenantContextAsync();

        // Assert
        tenantContext.Should().NotBeNull();
        tenantContext.TenantId.Should().Be(_fixture.TestTenantId);
    }
}
