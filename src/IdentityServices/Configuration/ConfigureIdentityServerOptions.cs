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
        options.IssuerUri = octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/");

        // AB#4989/AB#4990: the license key is no longer required at boot. Duende 8 keeps running
        // on a missing/expired license (log warnings only), which carries the fleet until the
        // OpenIddict swap removes Duende entirely.
        if (!string.IsNullOrWhiteSpace(octoIdentityOptions.Value.IdentityServerLicenseKey))
        {
            options.LicenseKey = octoIdentityOptions.Value.IdentityServerLicenseKey;
        }

        // Automatic Key Management is not included in the Duende Community Edition (V2) license
        // and Duende 8.x fails hard at startup when the option is enabled without the feature
        // licensed (AB#4988). We never used it: signing keys come from the static PKCS12
        // certificate registered via AddOctoSigningCredential (SigningCredentialService).
        options.KeyManagement.Enabled = false;

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