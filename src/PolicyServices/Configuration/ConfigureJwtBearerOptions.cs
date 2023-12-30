using Meshmakers.Common.Shared;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.PolicyServices.Configuration;

internal class ConfigureJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IOptions<OctoPolicyOptions> _policyServicesOptions;

    public ConfigureJwtBearerOptions(IOptions<OctoPolicyOptions> policyServicesOptions)
    {
        _policyServicesOptions = policyServicesOptions;
    }

    public void Configure(JwtBearerOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, JwtBearerOptions options)
    {
        options.Authority = _policyServicesOptions.Value.AuthorityUrl.EnsureEndsWith("/");
    }
}