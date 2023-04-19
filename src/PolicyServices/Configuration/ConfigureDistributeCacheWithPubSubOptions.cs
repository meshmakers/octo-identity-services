using Meshmakers.Octo.Backend.DistributedCache;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.PolicyServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureDistributeCacheWithPubSubOptions : IConfigureNamedOptions<DistributeCacheWithPubSubOptions>
{
    private readonly IOptions<OctoPolicyOptions> _octoPolicyServiceOptions;

    public ConfigureDistributeCacheWithPubSubOptions(IOptions<OctoPolicyOptions> octoPolicyServiceOptions)
    {
        _octoPolicyServiceOptions = octoPolicyServiceOptions;
    }


    public void Configure(DistributeCacheWithPubSubOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string name, DistributeCacheWithPubSubOptions options)
    {
        options.Host = _octoPolicyServiceOptions.Value.RedisCacheHost;
        options.Password = _octoPolicyServiceOptions.Value.RedisCachePassword;
    }
}
