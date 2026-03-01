using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.AzureEntraId;

internal class AzureEntraIdAuthSchemeCreator : IAuthSchemeCreator<RtAzureEntraIdIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<OpenIdConnectOptions> _openIdConnectAuthOptions;

    /// <summary>
    ///     ctor
    /// </summary>
    /// <param name="openIdConnectAuthOptions">Authentication builder for OpenId provider</param>
    public AzureEntraIdAuthSchemeCreator(IDynamicAuthOptionsBuilder<OpenIdConnectOptions> openIdConnectAuthOptions)
    {
        _openIdConnectAuthOptions = openIdConnectAuthOptions;
    }

    public AuthenticationScheme Create(RtAzureEntraIdIdentityProvider identityProvider, string? schemeNameOverride = null)
    {
        var schemeName = schemeNameOverride ?? identityProvider.Name;
        var options = _openIdConnectAuthOptions.CreateOptions(schemeName);

        options.Authority = $"https://login.microsoftonline.com/{identityProvider.TenantId}";
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;
        options.CallbackPath = "/auth/signin-callback";
        // Sign in to IdentityServer's external cookie scheme so ExternalLoginCallback can read it
        options.SignInScheme = AuthenticationConstants.IdentityServerConstants.ExternalCookieAuthenticationScheme;
        // Request email scope to get user's email address
        options.Scope.Add("email");
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.ValidAudience = identityProvider.ClientId;

        options.MetadataAddress = AuthenticationConstants.GetOidcMetadataAddress(options.Authority);

        options.ConfigurationManager = CreateOidcConfigurationManager(
            options.BackchannelHttpHandler,
            options.BackchannelTimeout,
            options.MetadataAddress,
            options.RequireHttpsMetadata);

        options.Validate();

        var displayName = identityProvider.DisplayName ?? identityProvider.Name;
        return new AuthenticationScheme(schemeName, displayName, typeof(OpenIdConnectHandler));
    }

    /// <summary>
    ///     Creates ConfigurationManager for <see cref="OpenIdConnectConfiguration" />.
    /// </summary>
    /// <param name="backchannelHttpHandler"></param>
    /// <param name="backchannelTimeout"></param>
    /// <param name="metadataAddress"></param>
    /// <param name="requireHttpsMetadata"></param>
    /// <returns></returns>
    private static IConfigurationManager<OpenIdConnectConfiguration> CreateOidcConfigurationManager(
        HttpMessageHandler? backchannelHttpHandler,
        TimeSpan backchannelTimeout,
        string metadataAddress,
        bool requireHttpsMetadata
    )
    {
        var httpClient = new HttpClient(backchannelHttpHandler ?? new HttpClientHandler())
        {
            Timeout = backchannelTimeout,
            MaxResponseContentBufferSize = 1024 * 1024 * 10
        };

        return new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(httpClient) { RequireHttps = requireHttpsMetadata }
        );
    }
}