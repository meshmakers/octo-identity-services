using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Common.DistributionEventHub.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureDistributionEventHubOptions(
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    IOptions<OctoSystemConfiguration> octoSystemConfiguration)
    : IConfigureNamedOptions<DistributionEventHubOptions>
{
    public void Configure(DistributionEventHubOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, DistributionEventHubOptions options)
    {
        options.InstancePrefix = octoIdentityOptions.Value.InstancePrefix;
        options.BrokerHost = octoIdentityOptions.Value.BrokerHost;
        options.BrokerUser = octoIdentityOptions.Value.BrokerUser;
        options.BrokerPassword = octoIdentityOptions.Value.BrokerPassword;
        options.RepositoryHost = octoSystemConfiguration.Value.DatabaseHost;
        options.RepositoryUser = octoSystemConfiguration.Value.DatabaseUser;
        options.RepositoryPassword = octoSystemConfiguration.Value.DatabaseUserPassword;
        options.DatabaseAuthenticationSource = octoSystemConfiguration.Value.AuthenticationDatabaseName;
    }
}