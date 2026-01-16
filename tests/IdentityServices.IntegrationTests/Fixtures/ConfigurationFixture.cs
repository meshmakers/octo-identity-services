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
    public string SystemDatabaseName => "IdentityIntegrationTests".ToLower();

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
