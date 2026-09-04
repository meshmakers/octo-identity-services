using IdentityServices.IntegrationTests.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
/// Fixture that loads configuration from appsettings.test.json.
/// </summary>
public abstract class ConfigurationFixture : ServiceCollectionFixture
{
    private readonly IntegrationTestConfiguration _configuration;

    /// <summary>
    /// Unique per fixture instance so unrelated fixtures can share one MongoDB server
    /// (<see cref="SharedMongoDbContainer" />) without colliding on the same database (AB#5117).
    /// </summary>
    public string SystemDatabaseName { get; } = $"identityintegrationtests{Guid.NewGuid():N}";

    /// <summary>
    /// Unique per fixture instance as well (AB#5117). A tenant id is the key of several
    /// <b>process-wide</b> caches and guards — most importantly
    /// <c>DefaultConfigurationCreatorServiceBase.TenantsInHandling</c>, a static dictionary that makes
    /// a concurrent <c>SetupAsync</c> for an id already being set up return without doing anything.
    /// With every fixture on the stock <c>octosystem</c>, parallel test collections would silently
    /// skip each other's CK model import and fail with <c>CkCacheException</c>.
    /// </summary>
    public string SystemTenantId { get; } = $"octosystem{Guid.NewGuid():N}"[..24];

    protected ConfigurationFixture()
    {
        _configuration = new IntegrationTestConfiguration();

        Services.Configure<IntegrationTestOptions>(options =>
            _configuration.GetSection("integrationTest").Bind(options));
    }

    protected T GetOptions<T>(string sectionName)
    {
        var option = Activator.CreateInstance<T>();
        _configuration.GetSection(sectionName).Bind(option);
        return option!;
    }
}
