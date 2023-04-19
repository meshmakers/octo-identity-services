using System;
using System.Net.Http;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Meshmakers.Octo.Backend.Authentication.Azure;

internal class AzureAuthSchemeCreator : IAuthSchemeCreator<AzureAdIdentityProvider>
{
    private readonly IDynamicAuthOptionsBuilder<OpenIdConnectOptions> _openIdConnectAuthOptions;

    /// <summary>
    ///     ctor
    /// </summary>
    /// <param name="openIdConnectAuthOptions">Authentication builder for OpenId provider</param>
    public AzureAuthSchemeCreator(IDynamicAuthOptionsBuilder<OpenIdConnectOptions> openIdConnectAuthOptions)
    {
        _openIdConnectAuthOptions = openIdConnectAuthOptions;
    }

    public AuthenticationScheme Create(AzureAdIdentityProvider identityProvider)
    {
        var options = _openIdConnectAuthOptions.CreateOptions(identityProvider.Alias);

        options.Authority = $"https://login.microsoftonline.com/{identityProvider.TenantId}";
        options.ClientId = identityProvider.ClientIdGroupAzureAd;
        options.ClientSecret = identityProvider.ClientSecretGroupAzureAd;
        options.CallbackPath = "/auth/signin-callback";
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.ValidAudience = identityProvider.ClientIdGroupAzureAd;

        options.MetadataAddress = AuthenticationConstants.GetOidcMetadataAddress(options.Authority);

        options.ConfigurationManager = CreateOidcConfigurationManager(
            options.BackchannelHttpHandler,
            options.BackchannelTimeout,
            options.MetadataAddress,
            options.RequireHttpsMetadata);

        options.Validate();

        return new AuthenticationScheme(identityProvider.Alias, identityProvider.Alias, typeof(OpenIdConnectHandler));
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
