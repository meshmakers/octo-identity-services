// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace IdentityServices.IntegrationTests.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
public class IntegrationTestOptions
{
    public string TenantId { get; set; } = "test-tenant";

    /// <summary>
    ///     The MongoDB image the Testcontainers fixture starts.
    /// </summary>
    /// <remarks>
    ///     🔴 <b>An exact patch version, never the floating <c>mongo:8.0</c> tag — do not "simplify"
    ///     it back.</b> On 2026-09-16 that tag moved to 8.0.28, which refuses to start on any Linux
    ///     kernel &gt;= 6.19 (SERVER-121912); Docker Desktop's VM kernel has reached 7.0.12-linuxkit.
    ///     <c>octo-mesh-adapter</c> was the one project in the estate still floating and its entire
    ///     integration suite died at once — Testcontainers surfaces it as a Docker "container is not
    ///     running" conflict out of <c>MongoDbBuilder.InitiateReplicaSetAsync</c>, which names
    ///     neither MongoDB nor the kernel and reads like broken fixture code. This value and the CI
    ///     lanes' pre-pull must stay in step.
    /// </remarks>
    public string MongoDbImage { get; set; } = "mongo:8.0.15";

    public string AdminUser { get; set; } = "octo-system-admin";

    public string AdminUserPassword { get; set; } = null!;

    public string DatabaseUserPassword { get; set; } = null!;

    public bool UseDirectConnection { get; set; }
}
