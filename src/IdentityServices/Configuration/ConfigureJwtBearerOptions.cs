using Meshmakers.Common.Shared;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IOptions<OctoIdentityServicesOptions> _octoIdentityOptions;

    public ConfigureJwtBearerOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    {
        _octoIdentityOptions = octoIdentityOptions;
    }


    public void Configure(JwtBearerOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, JwtBearerOptions options)
    {
        options.Authority = _octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/");
    }
}
