using IdentityServerPersistence.Services.Migrations;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.Migrations;

public class AbstractCollectionRootIndexMigrationTests
{
    private readonly AbstractCollectionRootIndexMigration _sut = new(
        NullLogger<AbstractCollectionRootIndexMigration>.Instance);

    private readonly ITenantContext _tenantContext = Substitute.For<ITenantContext>();
    private readonly IOctoAdminSession _adminSession = Substitute.For<IOctoAdminSession>();

    public AbstractCollectionRootIndexMigrationTests()
    {
        _tenantContext.TenantId.Returns("test-tenant");
    }

    [Fact]
    public async Task MigrateAsync_UpdatesIndexesOfTheWholeTenant()
    {
        var result = await _sut.MigrateAsync(_adminSession, _tenantContext);

        Assert.False(result.HasError);
        await _tenantContext.Received(1).UpdateIndexesAsync(_adminSession);
    }

    [Fact]
    public async Task MigrateAsync_WhenIndexUpdateThrows_ReturnsFailure()
    {
        _tenantContext.UpdateIndexesAsync(_adminSession).ThrowsAsync(new InvalidOperationException("boom"));

        var result = await _sut.MigrateAsync(_adminSession, _tenantContext);

        Assert.True(result.HasError);
        Assert.Contains("boom", result.ErrorText);
    }
}
