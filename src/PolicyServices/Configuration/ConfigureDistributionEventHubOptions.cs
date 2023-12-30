using Meshmakers.Octo.Common.DistributionEventHub.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.PolicyServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureDistributionEventHubOptions : IConfigureNamedOptions<DistributionEventHubOptions>
{
    private readonly IOptions<OctoPolicyOptions> _octoPolicyServiceOptions;
    private readonly IOptions<OctoSystemConfiguration> _octoSystemConfiguration;

    public ConfigureDistributionEventHubOptions(IOptions<OctoPolicyOptions> octoPolicyServiceOptions, 
        IOptions<OctoSystemConfiguration> octoSystemConfiguration)
    {
        _octoPolicyServiceOptions = octoPolicyServiceOptions;
        _octoSystemConfiguration = octoSystemConfiguration;
    }


    public void Configure(DistributionEventHubOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, DistributionEventHubOptions options)
    {
        options.BrokerHost = _octoPolicyServiceOptions.Value.BrokerHost;
        options.BrokerUser = _octoPolicyServiceOptions.Value.BrokerUser;
        options.BrokerPassword = _octoPolicyServiceOptions.Value.BrokerPassword;
        options.RepositoryHost = _octoSystemConfiguration.Value.DatabaseHost;
        options.RepositoryUser = _octoSystemConfiguration.Value.DatabaseUser;
        options.RepositoryPassword = _octoSystemConfiguration.Value.DatabaseUserPassword;
        options.DatabaseAuthenticationSource = _octoSystemConfiguration.Value.AuthenticationDatabaseName;
    }
}