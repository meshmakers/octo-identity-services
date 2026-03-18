using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Implements dynamic auth scheme service that allows to configure external identity
///     provider during run-time of identity services. Schemes are tenant-prefixed
///     (<c>{tenantId}:{providerName}</c>) so all tenants coexist safely in the singleton
///     <see cref="IAuthenticationSchemeProvider" />.
/// </summary>
internal class DynamicAuthSchemeService : IDynamicAuthSchemeService
{
    private readonly IAuthSchemeCreatorFactory _authSchemeCreatorFactory;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly ISystemContext _systemContext;
    private readonly ILogger<DynamicAuthSchemeService> _logger;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="systemContext">System context for accessing any tenant's repository directly</param>
    /// <param name="schemeProvider">Scheme provider</param>
    /// <param name="authSchemeCreatorFactory">Factory to resolve creators of auth providers.</param>
    /// <param name="logger">Logger</param>
    public DynamicAuthSchemeService(ISystemContext systemContext,
        IAuthenticationSchemeProvider schemeProvider,
        IAuthSchemeCreatorFactory authSchemeCreatorFactory,
        ILogger<DynamicAuthSchemeService> logger)
    {
        _systemContext = systemContext;
        _schemeProvider = schemeProvider;
        _authSchemeCreatorFactory = authSchemeCreatorFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task ConfigureAsync(string tenantId)
    {
        var prefix = $"{tenantId}:";

        // Remove only THIS tenant's schemes (not all schemes)
        var allSchemes = await _schemeProvider.GetAllSchemesAsync();
        foreach (var scheme in allSchemes.Where(s => s.Name.StartsWith(prefix, StringComparison.Ordinal)))
        {
            _schemeProvider.RemoveScheme(scheme.Name);
        }

        // Load identity providers directly from the tenant's database,
        // bypassing the scoped IOctoIdentityProviderStore which relies on HTTP context.
        var tenantRepo = await _systemContext.FindTenantRepositoryAsync(tenantId);
        var session = await tenantRepo.GetSessionAsync();
        session.StartTransaction();
        var result = await tenantRepo.GetRtEntitiesByTypeAsync<RtIdentityProvider>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();

        // Register schemes with tenant-prefixed names
        foreach (var identityProvider in result.Items)
        {
            if (!identityProvider.IsEnabled)
            {
                continue;
            }

            var schemeName = $"{prefix}{identityProvider.Name}";

            AuthenticationScheme scheme;
            switch (identityProvider)
            {
                case RtGoogleIdentityProvider googleIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtGoogleIdentityProvider>()
                        .Create(googleIdentityProvider, schemeName);
                    break;
                case RtMicrosoftIdentityProvider microsoftIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtMicrosoftIdentityProvider>()
                        .Create(microsoftIdentityProvider, schemeName);
                    break;
                case RtAzureEntraIdIdentityProvider rtAzureEntraIdIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtAzureEntraIdIdentityProvider>()
                        .Create(rtAzureEntraIdIdentityProvider, schemeName);
                    break;

                case RtOpenLdapIdentityProvider openLdapIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtOpenLdapIdentityProvider>()
                        .Create(openLdapIdentityProvider, schemeName);
                    break;

                case RtMicrosoftAdIdentityProvider microsoftAdIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtMicrosoftAdIdentityProvider>()
                        .Create(microsoftAdIdentityProvider, schemeName);
                    break;
                case RtFacebookIdentityProvider facebookIdentityProvider:
                    scheme = _authSchemeCreatorFactory.GetCreator<RtFacebookIdentityProvider>()
                        .Create(facebookIdentityProvider, schemeName);
                    break;
                case RtOctoTenantIdentityProvider:
                    // No ASP.NET auth scheme needed — cross-tenant auth is handled internally
                    // by CrossTenantAuthenticationService, not via OIDC redirect.
                    continue;
                default:
                    throw new InvalidOperationException(
                        $"Identity provider '{identityProvider.CkTypeId}' is not supported.");
            }

            _schemeProvider.AddScheme(scheme);
            _logger.LogDebug("Registered auth scheme '{SchemeName}' for tenant '{TenantId}'", schemeName, tenantId);
        }
    }
}
