using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Common.DistributionEventHub.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureDistributionEventHubOptions : IConfigureNamedOptions<DistributionEventHubOptions>
{
    private readonly IOptions<OctoIdentityServicesOptions> _octoIdentityOptions;
    private readonly IOptions<OctoSystemConfiguration> _octoSystemConfiguration;

    public ConfigureDistributionEventHubOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
        IOptions<OctoSystemConfiguration> octoSystemConfiguration)
    {
        _octoIdentityOptions = octoIdentityOptions;
        _octoSystemConfiguration = octoSystemConfiguration;
    }


    public void Configure(DistributionEventHubOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, DistributionEventHubOptions options)
    {
        options.BrokerHost = _octoIdentityOptions.Value.BrokerHost;
        options.BrokerUser = _octoIdentityOptions.Value.BrokerUser;
        options.BrokerPassword = _octoIdentityOptions.Value.BrokerPassword;
        options.RepositoryHost = _octoSystemConfiguration.Value.DatabaseHost;
        options.RepositoryUser = _octoSystemConfiguration.Value.DatabaseUser;
        options.RepositoryPassword = _octoSystemConfiguration.Value.DatabaseUserPassword;
        options.DatabaseAuthenticationSource = _octoSystemConfiguration.Value.AuthenticationDatabaseName;
    }
}