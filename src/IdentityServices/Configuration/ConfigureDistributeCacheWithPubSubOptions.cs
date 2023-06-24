using Meshmakers.Octo.Common.DistributedCache;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureDistributeCacheWithPubSubOptions : IConfigureNamedOptions<DistributeCacheWithPubSubOptions>
{
    private readonly IOptions<OctoIdentityServicesOptions> _octoIdentityOptions;

    public ConfigureDistributeCacheWithPubSubOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    {
        _octoIdentityOptions = octoIdentityOptions;
    }


    public void Configure(DistributeCacheWithPubSubOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, DistributeCacheWithPubSubOptions options)
    {
        options.Host = _octoIdentityOptions.Value.RedisCacheHost;
        options.Password = _octoIdentityOptions.Value.RedisCachePassword;
    }
}
