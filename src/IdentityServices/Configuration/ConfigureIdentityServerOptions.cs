using Duende.IdentityServer.Configuration;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureIdentityServerOptions(
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    IOptions<OctoSystemConfiguration> octoSystemConfiguration)
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

        // Configure Angular SPA routes for IdentityServer UI.
        // Uses the configured system tenant ID (default "OctoSystem") as the URL prefix.
        // TenantLoginRedirectMiddleware rewrites these to the actual tenant when acr_values is present.
        var systemTenantId = octoSystemConfiguration.Value.SystemTenantId;
        options.UserInteraction.LoginUrl = $"/{systemTenantId}/login";
        options.UserInteraction.LogoutUrl = $"/{systemTenantId}/logout";
        options.UserInteraction.ConsentUrl = $"/{systemTenantId}/consent";
        options.UserInteraction.ErrorUrl = $"/{systemTenantId}/error";
        options.UserInteraction.DeviceVerificationUrl = $"/{systemTenantId}/device";

        // RFC 7591 Dynamic Client Registration (AB#4338): advertise the hand-rolled /connect/register
        // endpoint in the discovery document so spec-compliant interactive MCP clients (e.g. Claude
        // Code) can discover it. Only advertised when DCR is enabled for the deployment.
        if (octoIdentityOptions.Value.DynamicClientRegistration.Enabled)
        {
            options.Discovery.CustomEntries["registration_endpoint"] =
                octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/") + "connect/register";
        }
    }
}