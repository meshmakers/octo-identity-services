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

    /// <summary>
    ///     Lets the shared MongoDB container acknowledge majority writes without waiting for the journal flush
    ///     (<c>writeConcernMajorityJournalDefault: false</c>). Off by default, so a local run behaves as
    ///     before; the CI pipeline switches it on with <c>OCTO_IT_integrationTest__MongoDbRelaxedDurability=true</c>.
    ///     The suite's data is throw-away, so a crash losing the last moments of writes is irrelevant.
    /// </summary>
    /// <remarks>
    ///     Why: with <c>maxParallelThreads</c> 4 the parallel tenant setups commit transactions through the one
    ///     replica-set container; on the CI agents those commits and writes took 78-158 s without any lock wait
    ///     and cancelled the setup (CI hang evidence). The repository clients write with <c>w: majority</c> and a
    ///     30 s <c>wtimeout</c> and no <c>j</c>, so this setting removes the journal flush from the commit path;
    ///     whether that is the slow part is a hypothesis that the CI runs with and without the switch measure.
    ///     The data stays on disk: a tmpfs data directory was measured and does not fit (about 2.6 GB after 13 min
    ///     of the suite, more than a CI agent can spare in RAM).
    /// </remarks>
    public bool MongoDbRelaxedDurability { get; set; }

    public string AdminUser { get; set; } = "octo-system-admin";

    public string AdminUserPassword { get; set; } = null!;

    public string DatabaseUserPassword { get; set; } = null!;

    public bool UseDirectConnection { get; set; }
}
