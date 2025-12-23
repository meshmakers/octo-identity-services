using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Implements dynamic auth scheme service that allows to configure external identity
///     provider during run-time of identity services.
/// </summary>
internal class DynamicAuthSchemeService : IDynamicAuthSchemeService
{
    private static readonly string[] ExcludedSchemes =
    {
        AuthenticationConstants.IdentityServerConstants.ExternalCookieAuthenticationScheme,
        AuthenticationConstants.IdentityServerConstants.SignoutScheme,
        AuthenticationConstants.BearerAuthenticationScheme, IdentityConstants.ApplicationScheme,
        IdentityConstants.ExternalScheme, IdentityConstants.TwoFactorRememberMeScheme,
        IdentityConstants.TwoFactorUserIdScheme
    };

    private readonly IAuthSchemeCreatorFactory _authSchemeCreatorFactory;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IOctoIdentityProviderStore _identityProviderStore;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="identityProviderStore">Data storage of identity providers</param>
    /// <param name="schemeProvider">Scheme provider</param>
    /// <param name="authSchemeCreatorFactory">Factory to resolve creators of auth providers.</param>
    public DynamicAuthSchemeService(IOctoIdentityProviderStore identityProviderStore,
        IAuthenticationSchemeProvider schemeProvider,
        IAuthSchemeCreatorFactory authSchemeCreatorFactory)
    {
        _identityProviderStore = identityProviderStore;
        _schemeProvider = schemeProvider;
        _authSchemeCreatorFactory = authSchemeCreatorFactory;
    }

    /// <inheritdoc />
    public async Task ConfigureAsync(string tenantId)
    {
        // Remove all schemes
        var allSchemes = await _schemeProvider.GetAllSchemesAsync();
        var filteredSchemes = allSchemes.Where(x => !ExcludedSchemes.Contains(x.Name));
        foreach (var authenticationScheme in filteredSchemes)
        {
            _schemeProvider.RemoveScheme(authenticationScheme.Name);
        }

        // Add schemes based on identity providers
        var identityProviders = await _identityProviderStore.GetAllAsync();
        foreach (var identityProvider in identityProviders)
        {
            if (!identityProvider.IsEnabled)
            {
                continue;
            }

            AuthenticationScheme scheme;
            switch (identityProvider)
            {
                case RtGoogleIdentityProvider googleIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtGoogleIdentityProvider>()
                        .Create(googleIdentityProvider);
                    break;
                case RtMicrosoftIdentityProvider microsoftIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtMicrosoftIdentityProvider>()
                        .Create(microsoftIdentityProvider);
                    break;
                case RtAzureEntraIdIdentityProvider rtAzureEntraIdIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtAzureEntraIdIdentityProvider>()
                        .Create(rtAzureEntraIdIdentityProvider);
                    break;

                case RtOpenLdapIdentityProvider openLdapIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtOpenLdapIdentityProvider>()
                        .Create(openLdapIdentityProvider);
                    break;

                case RtMicrosoftAdIdentityProvider microsoftAdIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtMicrosoftAdIdentityProvider>()
                        .Create(microsoftAdIdentityProvider);
                    break;
                case RtFacebookIdentityProvider facebookIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtFacebookIdentityProvider>()
                        .Create(facebookIdentityProvider);
                    break;
                default:
                    throw new NotImplementedException(
                        $"Identity provider '{identityProvider.CkTypeId}' is not supported.");
            }

            _schemeProvider.AddScheme(scheme);
        }
    }
}