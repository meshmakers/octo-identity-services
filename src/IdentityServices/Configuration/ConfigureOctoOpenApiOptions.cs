using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Services.Swagger;
using Meshmakers.Octo.Services.Swagger.Configuration;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureOctoOpenApiOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    : IConfigureNamedOptions<OctoOpenApiOptions>
{
    public void Configure(OctoOpenApiOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, OctoOpenApiOptions options)
    {
        options.AuthorityUrl = octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/");
    }
}