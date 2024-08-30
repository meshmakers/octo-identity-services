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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace IdentityServerPersistence.Services;

internal class DefaultConfigurationCreatorService(
    ILogger<DefaultConfigurationCreatorService> logger,
    ISystemContext systemContext,
    IDiagnosticsService diagnosticsService,
    RoleManager<RtRole> roleManager,
    IOctoClientStore clientStore,
    IOctoResourceStore resourceStore,
    IOctoIdentityProviderStore octoIdentityProviderStore,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions)
    : DefaultConfigurationCreatorServiceBase(logger)
{
    public override async Task InitializeAsync()
    {
        // Reconfigure the log level based on the configuration
        await diagnosticsService.ReconfigureLogLevelAsync(octoIdentityOptions.Value.MinLogLevel);

        await base.InitializeAsync();
    }

    protected override async Task SetupTenantAsync(string tenantId)
    {
        if (tenantId != systemContext.TenantId)
        {
            // Currently we only support the system tenant.
            return;
        }
        
        if (!await systemContext.IsSystemTenantExistingAsync())
        {
            await systemContext.CreateSystemTenantAsync();
        }

        await ImportCkModel();

        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();

        var identityConfiguration =
            await systemContext.GetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                new DefaultConfigurationVersion { Version = -1 });
        if (identityConfiguration == null || identityConfiguration.Version < IdentityServiceConstants.IdentitySchemaVersionValue)
        {
            await CreateClients();
            await CreateUsersAndRoles();

            await CreateApiScopes();
            await CreateApiResources();
            await CreateIdentityResources();
            await CreateIdentityProvider();

            await systemContext.SetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                new DefaultConfigurationVersion { Version = IdentityServiceConstants.IdentitySchemaVersionValue });
        }

        await session.CommitTransactionAsync();
    }

    private async Task ImportCkModel()
    {
        if (!await systemContext.IsCkModelExistingAsync(SystemIdentityCkIds.ModelId))
        {
            // We ensure that at least the system tenant contains a valid ck model.Other tenants
            // need to be enabled manually by a admin.
            OperationResult operationResult = new();
            await systemContext.ImportCkModelAsync(SystemIdentityCkIds.ModelId, operationResult);
            if (operationResult.HasErrors || operationResult.HasFatalErrors)
            {
                throw InitializationException.ImportCkModelFailed(systemContext.TenantId, operationResult.GetMessages());
            }
        }
    }

    private async Task CreateIdentityProvider()
    {
        var googleProvider = await octoIdentityProviderStore.GetByNameAsync(CommonConstants.GoogleIdentityProvider);
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

            await octoIdentityProviderStore.StoreAsync(googleProvider);
        }

        var microsoftProvider = await octoIdentityProviderStore.GetByNameAsync(CommonConstants.MicrosoftIdentityProvider);
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

            await octoIdentityProviderStore.StoreAsync(microsoftProvider);
        }
    }

    private async Task CreateApiScopes()
    {
        await resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.IdentityApiFullAccess,
            CommonConstants.IdentityApiFullAccessDisplayName));
        await resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.IdentityApiReadOnly,
            CommonConstants.IdentityApiReadOnlyDisplayName));
    }

    private async Task CreateApiResources()
    {
        await resourceStore.GetOrCreateApiResourceAsync(new RtApiResource
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
        await resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResources.OpenId());
        await resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResources.Profile());
        await resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResources.Email());
        await resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResource
        {
            Name = JwtClaimTypes.Role,
            DisplayName = IdentityTexts.Backend_Identity_UserSchema_Roles_DisplayName,
            Description = IdentityTexts.Backend_Identity_UserSchema_Roles_Description,
            UserClaims = new List<string> { JwtClaimTypes.Role }
        });
    }

    private async Task CreateUsersAndRoles()
    {
        await TryCreateRole(CommonConstants.TenantManagementRole);
        await TryCreateRole(CommonConstants.UserManagementRole);
        await TryCreateRole(CommonConstants.CommunicationManagementRole);
        await TryCreateRole(CommonConstants.DevelopmentRole);
        await TryCreateRole(CommonConstants.AdminPanelManagementRole);
        await TryCreateRole(CommonConstants.BotManagementRole);
        await TryCreateRole(CommonConstants.DashboardManagementRole);
        await TryCreateRole(CommonConstants.DashboardViewerRole);
    }

    private async Task TryCreateRole(string roleName)
    {
        var rtRole = await roleManager.FindByNameAsync(roleName);
        if (rtRole == null)
        {
            rtRole = new RtRole
            {
                Name = roleName,
                Claims = new AttributeRecordValueList<RtRoleClaimRecord>()
            };
            await roleManager.CreateAsync(rtRole);
        }
    }

    private async Task CreateClients()
    {
        var octoToolClient = await clientStore.FindClientByIdAsync(CommonConstants.OctoToolClientId);
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

            await clientStore.CreateAsync(appClient);
        }

        var octoIdentityServiceSwaggerClient =
            await clientStore.FindClientByIdAsync(CommonConstants.IdentityServicesSwaggerClientId);
        if (octoIdentityServiceSwaggerClient == null)
        {
            var appClient = new RtClient
            {
                Enabled = true,
                ClientId = CommonConstants.IdentityServicesSwaggerClientId,

                ClientName = IdentityTexts.Backend_IdentityServices_UserSchema_Swagger_DisplayName,
                ClientUri = octoIdentityOptions.Value.AuthorityUrl,

                AllowedGrantTypes = new AttributeStringValueList { OidcConstants.GrantTypes.AuthorizationCode },

                RequirePkce = true,
                RequireClientSecret = false,

                AccessTokenType = RtTokenTypeEnum.Jwt,
                AllowAccessTokensViaBrowser = true,
                AlwaysIncludeUserClaimsInIdToken = true,

                RedirectUris =
                {
                    octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/swagger/oauth2-redirect.html")
                },

                PostLogoutRedirectUris = { octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/") },
                AllowedCorsOrigins = { octoIdentityOptions.Value.AuthorityUrl.TrimEnd('/') },
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
            await clientStore.CreateAsync(appClient);
        }
    }
}