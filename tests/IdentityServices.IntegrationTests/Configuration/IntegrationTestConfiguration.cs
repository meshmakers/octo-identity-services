using Microsoft.Extensions.Configuration;

namespace IdentityServices.IntegrationTests.Configuration;

public class IntegrationTestConfiguration
{
    private readonly IConfiguration _configuration = new ConfigurationBuilder()
        .AddJsonFile("appsettings.test.json", true)
        .Build();

    public IConfigurationSection GetSection(string section)
    {
        return _configuration.GetSection(section);
    }
}
