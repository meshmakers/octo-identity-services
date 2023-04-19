using System;
using System.Linq;
using System.Threading.Tasks;
using Meshmakers.Octo.Backend.DistributedCache;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Meshmakers.Octo.SystematizedData.Persistence.SystemStores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

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
    private readonly IOctoIdentityProviderStore _sgIdentityProviderStore;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="sgIdentityProviderStore">Data storage of identity providers</param>
    /// <param name="schemeProvider">Scheme provider</param>
    /// <param name="authSchemeCreatorFactory">Factory to resolve creators of auth providers.</param>
    /// <param name="distributedCache">Memory cache do distribute events (if identity providers has changed.</param>
    public DynamicAuthSchemeService(IOctoIdentityProviderStore sgIdentityProviderStore,
        IAuthenticationSchemeProvider schemeProvider,
        IAuthSchemeCreatorFactory authSchemeCreatorFactory,
        IDistributedWithPubSubCache distributedCache)
    {
        _sgIdentityProviderStore = sgIdentityProviderStore;
        _schemeProvider = schemeProvider;
        _authSchemeCreatorFactory = authSchemeCreatorFactory;

        var channel = distributedCache.Subscribe<string>(CacheCommon.KeyIdentityProviderUpdate);
        channel.OnMessage(async _ => { await ConfigureAsync(); });
    }

    /// <inheritdoc />
    public async Task ConfigureAsync()
    {
        // Remove all schemes
        var allSchemes = await _schemeProvider.GetAllSchemesAsync();
        var filteredSchemes = allSchemes.Where(x => !ExcludedSchemes.Contains(x.Name));
        foreach (var authenticationScheme in filteredSchemes)
        {
            _schemeProvider.RemoveScheme(authenticationScheme.Name);
        }

        // Add schemes based on identity providers
        var identityProviders = await _sgIdentityProviderStore.GetAllAsync();
        foreach (var identityProvider in identityProviders)
        {
            if (!identityProvider.IsEnabled)
            {
                continue;
            }

            AuthenticationScheme scheme;
            switch (identityProvider)
            {
                case GoogleIdentityProvider googleIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<GoogleIdentityProvider>()
                        .Create(googleIdentityProvider);
                    break;
                case MicrosoftIdentityProvider microsoftIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<MicrosoftIdentityProvider>()
                        .Create(microsoftIdentityProvider);
                    break;
                case AzureAdIdentityProvider azureAdIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<AzureAdIdentityProvider>()
                        .Create(azureAdIdentityProvider);
                    break;
                
                case OpenLdapIdentityProvider openLdapIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<OpenLdapIdentityProvider>()
                        .Create(openLdapIdentityProvider);
                    break;
                
                case MicrosoftAdIdentityProvider microsoftAdIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<MicrosoftAdIdentityProvider>()
                        .Create(microsoftAdIdentityProvider);
                    break;
                
                default:
                    throw new NotImplementedException(
                        $"Identity provider '{identityProvider.Type}' is not supported.");
            }

            _schemeProvider.AddScheme(scheme);
        }
    }
}
