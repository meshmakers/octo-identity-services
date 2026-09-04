using Meshmakers.Octo.Runtime.Contracts.MongoDb;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
/// Main fixture for Identity Services integration tests.
/// Initializes MongoDB, system tenant, and test tenant.
/// </summary>
public class IdentityServicesFixture : DatabaseFixture
{
    /// <summary>
    /// Id — and therefore database name — of this fixture's test tenant. Unique per fixture instance
    /// (AB#5117): a tenant database name is a server-wide namespace, so the former fixed
    /// <c>test-tenant</c> collides as soon as a second fixture creates it on the shared
    /// <see cref="SharedMongoDbContainer" />. Every test reaches the tenant through this property,
    /// never through the literal.
    /// </summary>
    public string TestTenantId { get; }

    public IdentityServicesFixture()
    {
        TestTenantId = $"{_options.TenantId}-{Guid.NewGuid():N}"[..24];
    }

    protected override async Task InitializeServicesAsync()
    {
        await base.InitializeServicesAsync();

        // Initialize system tenant
        var systemContext = GetSystemContext();

        // Ensure clean state - delete if exists
        for (int i = 0; i < 10; i++)
        {
            try
            {
                if (i == 0 && await systemContext.IsSystemTenantExistingAsync())
                {
                    await systemContext.DeleteSystemTenantAsync();
                }

                if (await systemContext.IsSystemTenantExistingAsync())
                {
                    await Task.Delay(1000);
                    continue;
                }

                break;
            }
            catch (TenantException)
            {
                // Ignore tenant exceptions during cleanup
            }
        }

        // Create system tenant
        await systemContext.CreateSystemTenantAsync();

        // Create test tenant
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();

        try
        {
            await systemContext.CreateChildTenantAsync(session, TestTenantId, TestTenantId);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    /// <summary>
    /// Gets a tenant context for the test tenant.
    /// </summary>
    public async Task<ITenantContext> GetTestTenantContextAsync()
    {
        EnsureInitialized();

        var systemContext = GetSystemContext();
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();

        try
        {
            var tenantContext = await systemContext.GetChildTenantContextAsync(session, TestTenantId);
            await session.CommitTransactionAsync();
            return tenantContext;
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }
}
