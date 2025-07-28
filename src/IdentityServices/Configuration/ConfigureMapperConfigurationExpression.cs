using AutoMapper;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

public class ConfigureMapperConfigurationExpression(IOptions<OctoIdentityServicesOptions> octoIdentityOptions): IConfigureNamedOptions<MapperConfigurationExpression>
{
    public void Configure(MapperConfigurationExpression options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, MapperConfigurationExpression options)
    {
        if (string.IsNullOrWhiteSpace(octoIdentityOptions.Value.AutoMapperLicenseKey))
        {
            throw InitializationException.EnsureLicenseKey(
                "AutoMapper",
                "OCTO_IDENTITY__AutoMapperLicenseKey");
        }

        options.LicenseKey = octoIdentityOptions.Value.AutoMapperLicenseKey;
    }
}