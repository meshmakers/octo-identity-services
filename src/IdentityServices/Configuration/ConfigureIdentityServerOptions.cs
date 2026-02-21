using Duende.IdentityServer.Configuration;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureIdentityServerOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    : IConfigureNamedOptions<IdentityServerOptions>
{
    public void Configure(IdentityServerOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, IdentityServerOptions options)
    {
        if (string.IsNullOrWhiteSpace(octoIdentityOptions.Value.IdentityServerLicenseKey))
        {
            throw InitializationException.EnsureLicenseKey(
                "IdentityServer",
                "OCTO_IDENTITY__IdentityServerLicenseKey");
        }

        options.IssuerUri = octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/");
        options.LicenseKey = octoIdentityOptions.Value.IdentityServerLicenseKey;

        // Configure Angular SPA routes for IdentityServer UI
        options.UserInteraction.LoginUrl = "/System/login";
        options.UserInteraction.LogoutUrl = "/System/logout";
        options.UserInteraction.ConsentUrl = "/System/consent";
        options.UserInteraction.ErrorUrl = "/System/error";
        options.UserInteraction.DeviceVerificationUrl = "/System/device";
    }
}