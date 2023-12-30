using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.Swagger;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureOctoSwaggerOptions : IConfigureNamedOptions<OctoSwaggerOptions>
{
    private readonly IOptions<OctoIdentityServicesOptions> _octoIdentityOptions;

    public ConfigureOctoSwaggerOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    {
        _octoIdentityOptions = octoIdentityOptions;
    }

    public void Configure(OctoSwaggerOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, OctoSwaggerOptions options)
    {
        options.AuthorityUrl = _octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/");
    }
}