using Microsoft.Extensions.Configuration;

namespace IdentityServices.IntegrationTests.Configuration;

public class IntegrationTestConfiguration
{
    private readonly IConfiguration _configuration = new ConfigurationBuilder()
        .AddJsonFile("appsettings.test.json", true)
        // CI-only switches without touching the checked-in file, e.g.
        // OCTO_IT_integrationTest__MongoDbRelaxedDurability=true (AB#9375).
        .AddEnvironmentVariables("OCTO_IT_")
        .Build();

    public IConfigurationSection GetSection(string section)
    {
        return _configuration.GetSection(section);
    }
}
