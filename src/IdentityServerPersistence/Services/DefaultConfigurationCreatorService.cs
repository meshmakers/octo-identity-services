using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace IdentityServerPersistence.Services;

internal class DefaultConfigurationCreatorService : IDefaultConfigurationCreatorService
{
    private readonly IOctoClientStore _clientStore;
    private readonly IOctoIdentityProviderStore _octoIdentityProviderStore;
    private readonly OctoIdentityServicesOptions _octoIdentityServicesOptions;
    private readonly IOctoResourceStore _resourceStore;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly ISystemContext _systemContext;

    public DefaultConfigurationCreatorService(ISystemContext systemContext,
        RoleManager<RtRole> roleManager, IOctoClientStore clientStore, IOctoResourceStore resourceStore,
        IOctoIdentityProviderStore octoIdentityProviderStore, IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    {
        _systemContext = systemContext;
        _roleManager = roleManager;
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _octoIdentityProviderStore = octoIdentityProviderStore;
        _octoIdentityServicesOptions = octoIdentityOptions.Value;
    }

    public async Task SetupAsync(string tenantId)
    {
        if (tenantId != _systemContext.TenantId)
        {
            // Currently we only support the system tenant.
            return;
        }
        
        if (!await _systemContext.IsSystemTenantExistingAsync())
        {
            await _systemContext.CreateSystemTenantAsync();
        }

        await ImportCkModel();

        using var session = await _systemContext.GetSystemSessionAsync();
        session.StartTransaction();

        var identityConfiguration =
            await _systemContext.GetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                new DefaultConfigurationVersion { Version = -1 });
        if (identityConfiguration == null || identityConfiguration.Version < IdentityServiceConstants.IdentitySchemaVersionValue)
        {
            await CreateClients();
            await CreateUsersAndRoles();

            await CreateApiScopes();
            await CreateApiResources();
            await CreateIdentityResources();
            await CreateIdentityProvider();

            await _systemContext.SetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                new DefaultConfigurationVersion { Version = IdentityServiceConstants.IdentitySchemaVersionValue });
        }

        await session.CommitTransactionAsync();
    }

    private async Task ImportCkModel()
    {
        if (!await _systemContext.IsCkModelExistingAsync(SystemIdentityCkIds.ModelId))
        {
            // We ensure that at least the system tenant contains a valid ck model.Other tenants
            // need to be enabled manually by a admin.
            OperationResult operationResult = new();
            await _systemContext.ImportCkModelAsync(SystemIdentityCkIds.ModelId, operationResult);
            if (operationResult.HasErrors || operationResult.HasFatalErrors)
            {
                throw InitializationException.ImportCkModelFailed(_systemContext.TenantId, operationResult.GetMessages());
            }
        }
    }

    private async Task CreateIdentityProvider()
    {
        var googleProvider = await _octoIdentityProviderStore.GetByNameAsync(CommonConstants.GoogleIdentityProvider);
        if (googleProvider == null)
        {
            googleProvider = new RtGoogleIdentityProvider
            {
                IsEnabled = false,
                ClientId = "392724150963-34b8f10j23nm1rg31vi64lrb07o3aaga.apps.googleusercontent.com",
                ClientSecret = "***REMOVED-LEGACY-SECRET-AB3837***",
                Name = CommonConstants.GoogleIdentityProvider,
                DisplayName = CommonConstants.GoogleIdentityProvider
            };

            await _octoIdentityProviderStore.StoreAsync(googleProvider);
        }

        var microsoftProvider = await _octoIdentityProviderStore.GetByNameAsync(CommonConstants.MicrosoftIdentityProvider);
        if (microsoftProvider == null)
        {
            microsoftProvider = new RtMicrosoftIdentityProvider
            {
                IsEnabled = false,
                ClientId = "9697862a-d54b-429a-8526-8e0693c9ecba",
                ClientSecret = "z8H3]C/:VQ=bJE3jCXLP4F@L-/NwoI@J",
                Name = CommonConstants.MicrosoftIdentityProvider,
                DisplayName = CommonConstants.MicrosoftIdentityProvider
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
        await _resourceStore.GetOrCreateApiResourceAsync(new RtApiResource
        {
            Name = CommonConstants.IdentityApi,
            DisplayName = CommonConstants.IdentityApiDisplayName,
            Description = CommonConstants.IdentityApiDescription,
            Enabled = true,
            Scopes = new AttributeStringValueList
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
            adminRole = new RtRole
            {
                Name = CommonConstants.AdministratorsRole,
                Claims = new AttributeRecordValueList<RtRoleClaimRecord>()
            };
            await _roleManager.CreateAsync(adminRole);
        }

        var developerRole = await _roleManager.FindByNameAsync(CommonConstants.DevelopersRole);
        if (developerRole == null)
        {
            developerRole = new RtRole
            {
                Name = CommonConstants.DevelopersRole,
                Claims = new AttributeRecordValueList<RtRoleClaimRecord>()
            };
            await _roleManager.CreateAsync(developerRole);
        }

        var managerRole = await _roleManager.FindByNameAsync(CommonConstants.ManagersRole);
        if (managerRole == null)
        {
            managerRole = new RtRole
            {
                Name = CommonConstants.ManagersRole,
                Claims = new AttributeRecordValueList<RtRoleClaimRecord>()
            };
            await _roleManager.CreateAsync(managerRole);
        }

        var userRole = await _roleManager.FindByNameAsync(CommonConstants.UsersRole);
        if (userRole == null)
        {
            userRole = new RtRole
            {
                Name = CommonConstants.UsersRole,
                Claims = new AttributeRecordValueList<RtRoleClaimRecord>()
            };
            await _roleManager.CreateAsync(userRole);
        }
    }

    private async Task CreateClients()
    {
        var octoToolClient = await _clientStore.FindClientByIdAsync(CommonConstants.OctoToolClientId);
        if (octoToolClient == null)
        {
            var appClient = new RtClient
            {
                Enabled = true,
                ClientId = CommonConstants.OctoToolClientId,

                // no interactive user, use the clientId/secret for authentication
                AllowedGrantTypes = new AttributeStringValueList { OidcConstants.GrantTypes.DeviceCode },

                // secret for authentication
                ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
                {
                    new() { Value = CommonConstants.OctoToolClientSecret.Sha256() }
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
            var appClient = new RtClient
            {
                Enabled = true,
                ClientId = CommonConstants.IdentityServicesSwaggerClientId,

                ClientName = IdentityTexts.Backend_IdentityServices_UserSchema_Swagger_DisplayName,
                ClientUri = _octoIdentityServicesOptions.AuthorityUrl,

                AllowedGrantTypes = new AttributeStringValueList { OidcConstants.GrantTypes.AuthorizationCode },

                RequirePkce = true,
                RequireClientSecret = false,

                AccessTokenType = RtTokenTypeEnum.Jwt,
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