// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace IdentityServices.IntegrationTests.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
public class IntegrationTestOptions
{
    public string TenantId { get; set; } = "test-tenant";

    public string MongoDbImage { get; set; } = "mongo:8.0.15";

    public string AdminUser { get; set; } = "octo-system-admin";

    public string AdminUserPassword { get; set; } = null!;

    public string DatabaseUserPassword { get; set; } = null!;

    public bool UseDirectConnection { get; set; }
}
