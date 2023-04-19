using System.Collections.Generic;
using System.Threading.Tasks;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Common.Shared;
using Meshmakers.Octo.SystematizedData.Persistence;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Meshmakers.Octo.SystematizedData.Persistence.SystemStores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

internal class UserSchemaService : IUserSchemaService
{
    private readonly IOctoClientStore _clientStore;
    private readonly IOctoIdentityProviderStore _octoIdentityProviderStore;
    private readonly OctoIdentityServicesOptions _octoIdentityServicesOptions;
    private readonly IOctoResourceStore _resourceStore;
    private readonly RoleManager<OctoRole> _roleManager;
    private readonly ISystemContext _systemContext;
    private readonly UserManager<OctoUser> _userManager;

    public UserSchemaService(ISystemContext systemContext, UserManager<OctoUser> userManager,
        RoleManager<OctoRole> roleManager, IOctoClientStore clientStore, IOctoResourceStore resourceStore,
        IOctoIdentityProviderStore octoIdentityProviderStore, IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    {
        _systemContext = systemContext;
        _userManager = userManager;
        _roleManager = roleManager;
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _octoIdentityProviderStore = octoIdentityProviderStore;
        _octoIdentityServicesOptions = octoIdentityOptions.Value;
    }

    public async Task SetupAsync()
    {
        using var session = await _systemContext.StartSystemSessionAsync();
        session.StartTransaction();

        var version =
            await _systemContext.GetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                0);
        if (version < IdentityServiceConstants.IdentitySchemaVersionValue)
        {
            await CreateClients();
            await CreateUsersAndRoles();

            await CreateApiScopes();
            await CreateApiResources();
            await CreateIdentityResources();
            await CreateIdentityProvider();

            await _systemContext.SetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                IdentityServiceConstants.IdentitySchemaVersionValue);
        }

        await session.CommitTransactionAsync();
    }

    private async Task CreateIdentityProvider()
    {
        var googleProvider = await _octoIdentityProviderStore.GetAsync(CommonConstants.GoogleIdentityProvider);
        if (googleProvider == null)
        {
            googleProvider = new GoogleIdentityProvider
            {
                IsEnabled = false,
                ClientId = "392724150963-34b8f10j23nm1rg31vi64lrb07o3aaga.apps.googleusercontent.com",
                ClientSecret = "***REMOVED-LEGACY-SECRET-AB3837***",
                Type = IdentityProviderTypes.Google,
                Alias = CommonConstants.GoogleIdentityProvider
            };

            await _octoIdentityProviderStore.StoreAsync(googleProvider);
        }

        var microsoftProvider = await _octoIdentityProviderStore.GetAsync(CommonConstants.MicrosoftIdentityProvider);
        if (microsoftProvider == null)
        {
            microsoftProvider = new MicrosoftIdentityProvider
            {
                IsEnabled = false,
                ClientId = "9697862a-d54b-429a-8526-8e0693c9ecba",
                ClientSecret = "z8H3]C/:VQ=bJE3jCXLP4F@L-/NwoI@J",
                Type = IdentityProviderTypes.Microsoft,
                Alias = CommonConstants.MicrosoftIdentityProvider
            };

            await _octoIdentityProviderStore.StoreAsync(microsoftProvider);
        }
    }

    private async Task CreateApiScopes()
    {
        await _resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.IdentityApiFullAccess,
            CommonConstants.IdentityApiFullAccessDisplayName));
        await _resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.IdentityApiReadOnly,
            CommonConstants.IdentityApiReadOnlyDisplayName));
    }

    private async Task CreateApiResources()
    {
        await _resourceStore.GetOrCreateApiResourceAsync(new OctoApiResource
        {
            Name = CommonConstants.IdentityApi,
            DisplayName = CommonConstants.IdentityApiDisplayName,
            Description = CommonConstants.IdentityApiDescription,
            Enabled = true,
            Scopes = new List<string>
            {
                CommonConstants.IdentityApiFullAccess,
                CommonConstants.IdentityApiReadOnly
            }
        });
    }

    private async Task CreateIdentityResources()
    {
        await _resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResources.OpenId());
        await _resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResources.Profile());
        await _resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResources.Email());
        await _resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResource
        {
            Name = JwtClaimTypes.Role,
            DisplayName = IdentityTexts.Backend_Identity_UserSchema_Roles_DisplayName,
            Description = IdentityTexts.Backend_Identity_UserSchema_Roles_Description,
            UserClaims = new List<string> { JwtClaimTypes.Role }
        });
    }

    private async Task CreateUsersAndRoles()
    {
        var adminRole = await _roleManager.FindByNameAsync(CommonConstants.AdministratorsRole);
        if (adminRole == null)
        {
            adminRole = new OctoRole
            {
                Name = CommonConstants.AdministratorsRole,
                Claims = new List<IdentityRoleClaim<string>>()
            };
            await _roleManager.CreateAsync(adminRole);
        }
        
        var developerRole = await _roleManager.FindByNameAsync(CommonConstants.DevelopersRole);
        if (developerRole == null)
        {
            developerRole = new OctoRole
            {
                Name = CommonConstants.DevelopersRole,
                Claims = new List<IdentityRoleClaim<string>>()
            };
            await _roleManager.CreateAsync(developerRole);
        }
        
        var managerRole = await _roleManager.FindByNameAsync(CommonConstants.ManagersRole);
        if (managerRole == null)
        {
            managerRole = new OctoRole
            {
                Name = CommonConstants.ManagersRole,
                Claims = new List<IdentityRoleClaim<string>>()
            };
            await _roleManager.CreateAsync(managerRole);
        }

        var userRole = await _roleManager.FindByNameAsync(CommonConstants.UsersRole);
        if (userRole == null)
        {
            userRole = new OctoRole
            {
                Name = CommonConstants.UsersRole,
                Claims = new List<IdentityRoleClaim<string>>()
            };
            await _roleManager.CreateAsync(userRole);
        }
    }

    private async Task CreateClients()
    {
        var octoToolClient = await _clientStore.FindClientByIdAsync(CommonConstants.OctoToolClientId);
        if (octoToolClient == null)
        {
            var appClient = new OctoClient
            {
                ClientId = CommonConstants.OctoToolClientId,

                // no interactive user, use the clientId/secret for authentication
                AllowedGrantTypes = new[] { OidcConstants.GrantTypes.DeviceCode },

                // secret for authentication
                ClientSecrets =
                {
                    new Secret(CommonConstants.OctoToolClientSecret.Sha256())
                },

                AllowOfflineAccess = true,

                // scopes that client has access to
                AllowedScopes =
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    JwtClaimTypes.Role,
                    CommonConstants.SystemApiFullAccess,
                    CommonConstants.IdentityApiFullAccess,
                    CommonConstants.BotApiFullAccess
                }
            };

            await _clientStore.CreateAsync(appClient);
        }

        var octoIdentityServiceSwaggerClient =
            await _clientStore.FindClientByIdAsync(CommonConstants.IdentityServicesSwaggerClientId);
        if (octoIdentityServiceSwaggerClient == null)
        {
            var appClient = new OctoClient
            {
                ClientId = CommonConstants.IdentityServicesSwaggerClientId,

                ClientName = IdentityTexts.Backend_IdentityServices_UserSchema_Swagger_DisplayName,
                ClientUri = _octoIdentityServicesOptions.AuthorityUrl,

                AllowedGrantTypes = new[] { OidcConstants.GrantTypes.AuthorizationCode },

                RequirePkce = true,
                RequireClientSecret = false,

                AccessTokenType = AccessTokenType.Jwt,
                AllowAccessTokensViaBrowser = true,
                AlwaysIncludeUserClaimsInIdToken = true,

                RedirectUris =
                {
                    _octoIdentityServicesOptions.AuthorityUrl.EnsureEndsWith("/swagger/oauth2-redirect.html")
                },

                PostLogoutRedirectUris = { _octoIdentityServicesOptions.AuthorityUrl.EnsureEndsWith("/") },
                AllowedCorsOrigins = { _octoIdentityServicesOptions.AuthorityUrl.TrimEnd('/') },
                AllowedScopes =
                {
                    CommonConstants.Scopes.OpenId,
                    CommonConstants.Scopes.Profile,
                    CommonConstants.Scopes.Email,
                    JwtClaimTypes.Role,
                    CommonConstants.IdentityApiFullAccess,
                    CommonConstants.IdentityApiReadOnly
                }
            };
            await _clientStore.CreateAsync(appClient);
        }
    }
}
