using Duende.IdentityServer.Configuration;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureIdentityServerOptions : IConfigureNamedOptions<IdentityServerOptions>
{
    private readonly IOptions<OctoIdentityServicesOptions> _octoIdentityOptions;

    public ConfigureIdentityServerOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    {
        _octoIdentityOptions = octoIdentityOptions;
    }

    public void Configure(IdentityServerOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, IdentityServerOptions options)
    {
        options.IssuerUri = _octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/");
    }
}