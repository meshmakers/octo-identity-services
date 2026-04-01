using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Migrations;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.ConstructionKit.Models.System.Generated.System.v2;
using Meshmakers.Octo.Runtime.Contracts.CkModelMigrations;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

// ReSharper disable once ClassNeverInstantiated.Global
internal class DefaultConfigurationCreatorService(
    ILogger<DefaultConfigurationCreatorService> logger,
    ISystemContext systemContext,
    IDiagnosticsService diagnosticsService,
    RoleManager<RtRole> roleManager,
    IOctoClientStore clientStore,
    IOctoResourceStore resourceStore,
    IOctoIdentityProviderStore octoIdentityProviderStore,
    IGroupStore groupStore,
    IOptions<OctoIdentityServicesOptions> octoIdentityOptions,
    MigrationService? migrationService,
    ICkModelUpgradeService? ckModelUpgradeService = null,
    IRuntimeRepositoryProvider? runtimeRepositoryProvider = null)
    : DefaultConfigurationCreatorServiceBase(logger), IConfigurationService
{
    private const string RefineryStudioClientId = "octo-data-refinery-studio";

    public override async Task InitializeAsync()
    {
        // Reconfigure the log level based on the configuration
        await diagnosticsService.ReconfigureLogLevelAsync(octoIdentityOptions.Value.MinLogLevel);

        await base.InitializeAsync();
    }

    protected override async Task SetupTenantAsync(string tenantId)
    {
        // Capture schema versions BEFORE any CK model updates
        // This must happen FIRST so we can detect version changes for migration
        IReadOnlyDictionary<string, string>? previousSchemaVersions = null;
        if (runtimeRepositoryProvider != null && ckModelUpgradeService != null)
        {
            previousSchemaVersions = await runtimeRepositoryProvider
                .GetSchemaVersionsAsync(tenantId, CancellationToken.None);

            if (previousSchemaVersions.Count > 0)
            {
                logger.LogDebug(
                    "Captured {Count} schema versions before import for tenant '{TenantId}'",
                    previousSchemaVersions.Count, tenantId);
            }
        }

        // 1st, we ensure that the system tenant and its ck model exists
        if (tenantId == systemContext.TenantId)
        {
            // Ensure that the system ck model is available with the current version,
            // This method ensures that the system repository database is already existing, but not
            // up-to-date.
            await systemContext.EnsureSystemCkModelAsync();

            // So upgrades are done now. If it still does not exist -> create it from scratch.
            if (!await systemContext.IsSystemTenantExistingAsync())
            {
                await systemContext.CreateSystemTenantAsync();
            }
        }

        var tenantContext = tenantId == systemContext.TenantId
            ? systemContext
            : await systemContext.GetChildTenantContextAsync(tenantId);

        // Ensure that the identity ck model and notification ck model is imported
        await ImportCkModel(tenantContext);

        // Run CK model data migrations (transforms existing runtime entities)
        await RunCkModelMigrationsAsync(tenantContext, previousSchemaVersions);

        // we run the infrastructure migrations for each tenant context
        if (migrationService != null)
        {
            var adminSession = await tenantContext.GetAdminSessionAsync();
            await migrationService.ExecuteMigrationsAsync(adminSession, tenantContext);
        }

        // Create default roles for every tenant (needed for cross-tenant role mapping)
        await CreateUsersAndRoles();

        // Create default groups (e.g. TenantOwners) for every tenant
        await CreateDefaultGroupsAsync();

        if (tenantId != systemContext.TenantId)
        {
            // Ensure identity data (resources, scopes, clients) exists in child tenants
            // so that OAuth/OIDC flows work when targeting a child tenant
            await EnsureIdentityDataInChildTenantAsync(tenantContext);

            // Ensure mail notification config and templates exist in child tenants
            var childRepo = tenantContext.GetTenantRepositoryAsAdmin();
            using var childSession = await tenantContext.GetAdminSessionAsync();
            childSession.StartTransaction();
            await CreateTenantConfiguration(childSession, childRepo);
            await childSession.CommitTransactionAsync();
            return;
        }

        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();

        var identityConfiguration =
            await systemContext.GetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                new DefaultConfigurationVersion { Version = -1 });
        if (identityConfiguration == null ||
            identityConfiguration.Version < IdentityServiceConstants.IdentitySchemaVersionValue)
        {
            await CreateClients();

            await CreateApiScopes();
            await CreateApiResources();
            await CreateIdentityResources();
            await CreateIdentityProvider();
            await CreateTenantConfiguration(session, systemContext.GetSystemTenantRepositoryAsAdmin());

            await systemContext.SetConfigurationAsync(session, IdentityServiceConstants.IdentitySchemaVersionKey,
                new DefaultConfigurationVersion { Version = IdentityServiceConstants.IdentitySchemaVersionValue });
        }

        // Always ensure the Refinery Studio client is up-to-date, even when the schema version
        // hasn't changed. Its configuration depends on runtime settings (RefineryStudioUrl) and
        // may include critical flags like UpdateAccessTokenClaimsOnRefresh that must be applied
        // to existing clients without requiring a schema version bump.
        await EnsureRefineryStudioClientAsync();

        await session.CommitTransactionAsync();
    }

    private async Task ImportCkModel(ITenantContext tenantContext)
    {
        if (!await tenantContext.IsCkModelExistingAsync(SystemIdentityCkIds.CkModelId))
        {
            // Install the Identity CK model in all tenants (needed for cross-tenant authentication
            // and role mapping). The model is required for ExternalTenantUserMapping and
            // OctoTenantIdentityProvider entities.
            OperationResult operationResult = new();
            await tenantContext.ImportCkModelAsync(SystemIdentityCkIds.CkModelId, operationResult);
            if (operationResult.HasErrors || operationResult.HasFatalErrors)
            {
                throw InitializationException.ImportCkModelFailed(tenantContext.TenantId,
                    operationResult.GetMessages());
            }
        }

        if (!await tenantContext.IsCkModelExistingAsync(SystemNotificationCkIds.CkModelId))
        {
            // We ensure that at least the system tenant contains a valid ck model.Other tenants
            // need to be enabled manually by an admin.
            OperationResult operationResult = new();
            await tenantContext.ImportCkModelAsync(SystemNotificationCkIds.CkModelId, operationResult);
            if (operationResult.HasErrors || operationResult.HasFatalErrors)
            {
                throw InitializationException.ImportCkModelFailed(tenantContext.TenantId,
                    operationResult.GetMessages());
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

        var microsoftProvider =
            await octoIdentityProviderStore.GetByNameAsync(CommonConstants.MicrosoftIdentityProvider);
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
        await resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.OctoApiFullAccess,
            CommonConstants.OctoApiFullAccessDisplayName));
        await resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.OctoApiReadOnly,
            CommonConstants.OctoApiReadOnlyDisplayName));
        await resourceStore.TryCreateApiScopeAsync(new ApiScope(CommonConstants.OctoApiDataModelManagement,
            CommonConstants.OctoApiDataModelManagementDisplayName));
    }

    private async Task CreateApiResources()
    {
        await resourceStore.GetOrCreateApiResourceAsync(new RtApiResource
        {
            Name = CommonConstants.OctoApi,
            DisplayName = CommonConstants.OctoApiDisplayName,
            Description = CommonConstants.OctoApiDescription,
            Enabled = true,
            Scopes = new AttributeStringValueList
            {
                CommonConstants.OctoApiFullAccess,
                CommonConstants.OctoApiReadOnly,
                CommonConstants.OctoApiDataModelManagement
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
        await resourceStore.GetOrCreateIdentityResourceAsync(new IdentityResource
        {
            Name = "allowed_tenants",
            DisplayName = "Allowed Tenants",
            Description = "Tenants the user is allowed to access",
            UserClaims = new List<string> { "allowed_tenants" }
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
        await TryCreateRole(CommonConstants.ReportingManagementRole);
        await TryCreateRole(CommonConstants.ReportingViewerRole);
        await TryCreateRole(CommonConstants.DataModelManagementRole);
    }

    private async Task CreateDefaultGroupsAsync()
    {
        // Collect all default role RtIds
        var defaultRoleNames = new[]
        {
            CommonConstants.TenantManagementRole,
            CommonConstants.UserManagementRole,
            CommonConstants.CommunicationManagementRole,
            CommonConstants.DevelopmentRole,
            CommonConstants.AdminPanelManagementRole,
            CommonConstants.BotManagementRole,
            CommonConstants.DashboardManagementRole,
            CommonConstants.DashboardViewerRole,
            CommonConstants.ReportingManagementRole,
            CommonConstants.ReportingViewerRole,
            CommonConstants.DataModelManagementRole
        };

        var roleIds = new List<string>();
        foreach (var roleName in defaultRoleNames)
        {
            var role = await roleManager.FindByNameAsync(roleName);
            if (role != null)
            {
                roleIds.Add(role.RtId.ToString());
            }
        }

        var normalizedName = CommonConstants.TenantOwnersGroup.ToUpperInvariant();
        var existingGroup = await groupStore.FindByNameAsync(normalizedName);
        if (existingGroup == null)
        {
            var tenantOwnersGroup = new RtGroup
            {
                RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
                GroupName = CommonConstants.TenantOwnersGroup,
                NormalizedGroupName = normalizedName,
                GroupDescription = "Default group with all roles assigned. Members inherit all tenant permissions."
            };

            await groupStore.StoreAsync(tenantOwnersGroup);
            await groupStore.SetRoleIdsAsync(tenantOwnersGroup.RtId, roleIds);
        }
        else
        {
            // Ensure all current roles are included (new roles may have been added)
            await groupStore.SetRoleIdsAsync(existingGroup.RtId, roleIds);
        }
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
                CommonConstants.OctoApiFullAccess,
            }
        };

        var octoToolClient = await clientStore.FindClientByIdAsync(CommonConstants.OctoToolClientId);
        if (octoToolClient == null)
        {
            await clientStore.CreateAsync(appClient);
        }
        else
        {
            await clientStore.UpdateAsync(octoToolClient.ClientId, appClient);
        }

        appClient = new RtClient
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
                CommonConstants.OctoApiFullAccess,
                CommonConstants.OctoApiReadOnly,
            }
        };

        var octoIdentityServiceSwaggerClient =
            await clientStore.FindClientByIdAsync(CommonConstants.IdentityServicesSwaggerClientId);
        if (octoIdentityServiceSwaggerClient == null)
        {
            await clientStore.CreateAsync(appClient);
        }
        else
        {
            await clientStore.UpdateAsync(octoIdentityServiceSwaggerClient.ClientId, appClient);
        }

        await EnsureRefineryStudioClientAsync();
    }

    /// <summary>
    /// Ensures the Refinery Studio SPA OIDC client is up-to-date in the system tenant.
    /// Called unconditionally at startup (outside the schema version check) because its
    /// configuration depends on runtime settings and critical flags like
    /// <c>UpdateAccessTokenClaimsOnRefresh</c>.
    /// </summary>
    private async Task EnsureRefineryStudioClientAsync()
    {
        var refineryStudioUrl = octoIdentityOptions.Value.RefineryStudioUrl;
        if (string.IsNullOrWhiteSpace(refineryStudioUrl))
        {
            return;
        }

        var refineryStudioClient = new RtClient
        {
            Enabled = true,
            ClientId = RefineryStudioClientId,
            ClientName = "Data Refinery Studio",
            ClientUri = refineryStudioUrl,

            AllowedGrantTypes = new AttributeStringValueList { OidcConstants.GrantTypes.AuthorizationCode },

            RequirePkce = true,
            RequireClientSecret = false,
            RequireConsent = false,

            AccessTokenType = RtTokenTypeEnum.Jwt,
            AllowAccessTokensViaBrowser = true,
            AlwaysIncludeUserClaimsInIdToken = true,
            UpdateAccessTokenClaimsOnRefresh = true,

            RedirectUris = { refineryStudioUrl.EnsureEndsWith("/") },
            PostLogoutRedirectUris = { refineryStudioUrl.EnsureEndsWith("/") },
            AllowedCorsOrigins = { refineryStudioUrl.TrimEnd('/') },
            AllowOfflineAccess = true,

            AllowedScopes =
            {
                CommonConstants.Scopes.OpenId,
                CommonConstants.Scopes.Profile,
                CommonConstants.Scopes.Email,
                JwtClaimTypes.Role,
                "allowed_tenants",
                CommonConstants.OctoApiFullAccess,
            },

            FrontChannelLogoutUri = refineryStudioUrl.EnsureEndsWith("/logout/callback"),
            FrontChannelLogoutSessionRequired = true
        };

        var existingRefineryStudioClient = await clientStore.FindClientByIdAsync(RefineryStudioClientId);
        if (existingRefineryStudioClient == null)
        {
            await clientStore.CreateAsync(refineryStudioClient);
        }
        else
        {
            await clientStore.UpdateAsync(existingRefineryStudioClient.ClientId, refineryStudioClient);
        }
    }

    private async Task CreateTenantConfiguration(IOctoSession session, ITenantRepository tenantRepository)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.MailNotificationConfigurationName);
        var r = await tenantRepository.GetRtEntitiesByTypeAsync<RtMailNotificationConfiguration>(session,
            queryOptions);
        if (r.TotalCount == 0)
        {
            var rtMailNotificationConfiguration = new RtMailNotificationConfiguration
            {
                RtWellKnownName = IdentityServiceConstants.MailNotificationConfigurationName,
                EnableEmailNotifications = false
            };
            await tenantRepository.InsertOneRtEntityAsync(session, rtMailNotificationConfiguration);
        }

        queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.WelcomeEmailTemplateName);
        r = await tenantRepository.GetRtEntitiesByTypeAsync<RtMailNotificationConfiguration>(session,
            queryOptions);
        if (r.TotalCount == 0)
        {
            var welcomeMailTemplate = new RtNotificationTemplate
            {
                RtWellKnownName = IdentityServiceConstants.WelcomeEmailTemplateName,
                Type = RtNotificationTypesEnum.EMail,
                RenderingType = RtRenderingTypesEnum.Plain,
                SubjectTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailSubject,
                BodyTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailBody
            };
            await tenantRepository.InsertOneRtEntityAsync(session, welcomeMailTemplate);
        }

        queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.WelcomeEmailWithNoPasswordTemplateName);
        r = await tenantRepository.GetRtEntitiesByTypeAsync<RtMailNotificationConfiguration>(session,
            queryOptions);
        if (r.TotalCount == 0)
        {
            var welcomeMailWithNoPasswordTemplate = new RtNotificationTemplate
            {
                RtWellKnownName = IdentityServiceConstants.WelcomeEmailWithNoPasswordTemplateName,
                Type = RtNotificationTypesEnum.EMail,
                RenderingType = RtRenderingTypesEnum.Plain,
                SubjectTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailWithNoPasswordSubject,
                BodyTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_WelcomeMailWithNoPasswordBody
            };
            await tenantRepository.InsertOneRtEntityAsync(session, welcomeMailWithNoPasswordTemplate);
        }

        queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtEntity.RtWellKnownName),
                IdentityServiceConstants.ResetPasswordEmailTemplateName);
        r = await tenantRepository.GetRtEntitiesByTypeAsync<RtMailNotificationConfiguration>(session,
            queryOptions);
        if (r.TotalCount == 0)
        {
            var resetPasswordMailTemplate = new RtNotificationTemplate
            {
                RtWellKnownName = IdentityServiceConstants.ResetPasswordEmailTemplateName,
                Type = RtNotificationTypesEnum.EMail,
                RenderingType = RtRenderingTypesEnum.Plain,
                SubjectTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_ResetPasswordMailSubject,
                BodyTemplate = IdentityTexts.Backend_IdentityServices_UserSchema_ResetPasswordMailBody
            };
            await tenantRepository.InsertOneRtEntityAsync(session, resetPasswordMailTemplate);
        }
    }

    public Task EnableAsync(string tenantId)
    {
        return Task.CompletedTask;
    }

    public Task DisableAsync(string tenantId)
    {
        return Task.CompletedTask;
    }

    public Task<bool> IsEnabledAsync(string tenantId)
    {
        return Task.FromResult(true);
    }

    public bool CanBeEnabled()
    {
        return false;
    }

    private async Task EnsureIdentityDataInChildTenantAsync(ITenantContext tenantContext)
    {
        try
        {
            var childRepo = tenantContext.GetTenantRepositoryAsAdmin();
            using var session = await tenantContext.GetAdminSessionAsync();
            session.StartTransaction();

            // Identity Resources (required for all OAuth/OIDC flows)
            await EnsureIdentityResourceAsync(session, childRepo, "openid", "Your user identifier",
                required: true, claims: new[] { "sub" });
            await EnsureIdentityResourceAsync(session, childRepo, "profile", "User profile",
                claims: new[]
                {
                    "name", "family_name", "given_name", "middle_name", "nickname",
                    "preferred_username", "profile", "picture", "website", "gender",
                    "birthdate", "zoneinfo", "locale", "updated_at"
                });
            await EnsureIdentityResourceAsync(session, childRepo, "email", "Your email address",
                claims: new[] { "email", "email_verified" });
            await EnsureIdentityResourceAsync(session, childRepo, JwtClaimTypes.Role,
                IdentityTexts.Backend_Identity_UserSchema_Roles_DisplayName,
                description: IdentityTexts.Backend_Identity_UserSchema_Roles_Description,
                claims: new[] { JwtClaimTypes.Role });
            await EnsureIdentityResourceAsync(session, childRepo, "allowed_tenants",
                "Allowed Tenants",
                description: "Tenants the user is allowed to access",
                claims: new[] { "allowed_tenants" });

            // API Scopes
            await EnsureApiScopeAsync(session, childRepo,
                CommonConstants.OctoApiFullAccess, CommonConstants.OctoApiFullAccessDisplayName);
            await EnsureApiScopeAsync(session, childRepo,
                CommonConstants.OctoApiReadOnly, CommonConstants.OctoApiReadOnlyDisplayName);

            // API Resources
            await EnsureApiResourceAsync(session, childRepo,
                CommonConstants.OctoApi, CommonConstants.OctoApiDisplayName,
                CommonConstants.OctoApiDescription,
                new[] { CommonConstants.OctoApiFullAccess, CommonConstants.OctoApiReadOnly });

            // Roles (required for per-tenant user management and cross-tenant role mapping)
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.TenantManagementRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.UserManagementRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.CommunicationManagementRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.DevelopmentRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.AdminPanelManagementRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.BotManagementRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.DashboardManagementRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.DashboardViewerRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.ReportingManagementRole);
            await EnsureRoleInChildTenantAsync(session, childRepo, CommonConstants.ReportingViewerRole);

            // TenantOwners group
            await EnsureGroupInChildTenantAsync(session, childRepo);

            // Clients
            await EnsureClientInChildTenantAsync(session, childRepo, new RtClient
            {
                Enabled = true,
                ClientId = CommonConstants.OctoToolClientId,
                AllowedGrantTypes = new AttributeStringValueList { OidcConstants.GrantTypes.DeviceCode },
                ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
                {
                    new() { Value = CommonConstants.OctoToolClientSecret.Sha256() }
                },
                AllowOfflineAccess = true,
                AllowedScopes =
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    JwtClaimTypes.Role,
                    CommonConstants.OctoApiFullAccess,
                }
            });

            await EnsureClientInChildTenantAsync(session, childRepo, new RtClient
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
                    CommonConstants.OctoApiFullAccess,
                    CommonConstants.OctoApiReadOnly,
                }
            });

            // Refinery Studio SPA client (only if URL is configured)
            var refineryStudioUrl = octoIdentityOptions.Value.RefineryStudioUrl;
            if (!string.IsNullOrWhiteSpace(refineryStudioUrl))
            {
                await EnsureClientInChildTenantAsync(session, childRepo, new RtClient
                {
                    Enabled = true,
                    ClientId = RefineryStudioClientId,
                    ClientName = "Data Refinery Studio",
                    ClientUri = refineryStudioUrl,
                    AllowedGrantTypes =
                        new AttributeStringValueList { OidcConstants.GrantTypes.AuthorizationCode },
                    RequirePkce = true,
                    RequireClientSecret = false,
                    RequireConsent = false,
                    AccessTokenType = RtTokenTypeEnum.Jwt,
                    AllowAccessTokensViaBrowser = true,
                    AlwaysIncludeUserClaimsInIdToken = true,
                    UpdateAccessTokenClaimsOnRefresh = true,
                    RedirectUris = { refineryStudioUrl.EnsureEndsWith("/") },
                    PostLogoutRedirectUris = { refineryStudioUrl.EnsureEndsWith("/") },
                    AllowedCorsOrigins = { refineryStudioUrl.TrimEnd('/') },
                    AllowOfflineAccess = true,
                    AllowedScopes =
                    {
                        CommonConstants.Scopes.OpenId,
                        CommonConstants.Scopes.Profile,
                        CommonConstants.Scopes.Email,
                        JwtClaimTypes.Role,
                        CommonConstants.OctoApiFullAccess,
                    },
                    FrontChannelLogoutUri = refineryStudioUrl.EnsureEndsWith("/logout/callback"),
                    FrontChannelLogoutSessionRequired = true
                });
            }

            await session.CommitTransactionAsync();

            logger.LogInformation(
                "Ensured identity data (resources, scopes, roles, clients) exists in child tenant '{TenantId}'",
                tenantContext.TenantId);
        }
        catch (Exception e)
        {
            logger.LogWarning(e,
                "Failed to ensure identity data in child tenant '{TenantId}'. " +
                "Data will be created on next startup.",
                tenantContext.TenantId);
        }
    }

    private static async Task EnsureIdentityResourceAsync(
        IOctoSession session, ITenantRepository childRepo,
        string name, string displayName,
        string? description = null, bool required = false, string[]? claims = null)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtIdentityResource.Name), FieldFilterOperator.Equals, name);
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtIdentityResource>(session, queryOptions);
        if (!result.Items.Any())
        {
            var resource = new RtIdentityResource
            {
                Name = name,
                DisplayName = displayName,
                Description = description,
                Enabled = true,
                IsRequired = required,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(claims?.ToList() ?? new List<string>())
            };
            await childRepo.InsertOneRtEntityAsync(session, resource);
        }
    }

    private static async Task EnsureApiScopeAsync(
        IOctoSession session, ITenantRepository childRepo,
        string name, string displayName)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, name);
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtApiScope>(session, queryOptions);
        if (!result.Items.Any())
        {
            var scope = new RtApiScope
            {
                Name = name,
                DisplayName = displayName,
                Enabled = true
            };
            await childRepo.InsertOneRtEntityAsync(session, scope);
        }
    }

    private static async Task EnsureApiResourceAsync(
        IOctoSession session, ITenantRepository childRepo,
        string name, string displayName, string description, string[] scopes)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiResource.Name), FieldFilterOperator.Equals, name);
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtApiResource>(session, queryOptions);
        if (!result.Items.Any())
        {
            var resource = new RtApiResource
            {
                Name = name,
                DisplayName = displayName,
                Description = description,
                Enabled = true,
                Scopes = new AttributeStringValueList(scopes.ToList())
            };
            await childRepo.InsertOneRtEntityAsync(session, resource);
        }
    }

    private static async Task EnsureClientInChildTenantAsync(
        IOctoSession session, ITenantRepository childRepo, RtClient client)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, client.ClientId);
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtClient>(session, queryOptions);
        if (!result.Items.Any())
        {
            await childRepo.InsertOneRtEntityAsync(session, client);
        }
        else
        {
            await childRepo.ReplaceOneRtEntityByIdAsync(session, result.Items.First().RtId, client);
        }
    }

    private static async Task EnsureRoleInChildTenantAsync(
        IOctoSession session, ITenantRepository childRepo, string roleName)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, roleName.ToUpperInvariant());
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtRole>(session, queryOptions);
        if (!result.Items.Any())
        {
            var role = new RtRole
            {
                Name = roleName,
                NormalizedName = roleName.ToUpperInvariant(),
                Claims = new AttributeRecordValueList<RtRoleClaimRecord>()
            };
            await childRepo.InsertOneRtEntityAsync(session, role);
        }
    }

    private static async Task EnsureGroupInChildTenantAsync(
        IOctoSession session, ITenantRepository childRepo)
    {
        var normalizedName = CommonConstants.TenantOwnersGroup.ToUpperInvariant();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName), normalizedName);
        var result = await childRepo.GetRtEntitiesByTypeAsync<RtGroup>(session, queryOptions);

        // Collect all role RtIds in the child tenant
        var roleResult = await childRepo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        var roleIds = roleResult.Items.Select(r => r.RtId.ToString()).ToList();

        RtGroup group;
        if (!result.Items.Any())
        {
            group = new RtGroup
            {
                RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
                GroupName = CommonConstants.TenantOwnersGroup,
                NormalizedGroupName = normalizedName,
                GroupDescription = "Default group with all roles assigned. Members inherit all tenant permissions."
            };
            await childRepo.InsertOneRtEntityAsync(session, group);
        }
        else
        {
            group = result.Items.First();
        }

        // Ensure all role associations exist
        var groupEntityId = group.ToRtEntityId();
        var roleCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtRole>();

        // Get current role associations
        var currentAssociations = await childRepo.GetRtAssociationsAsync(
            session,
            groupEntityId,
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        var currentRoleIds = currentAssociations.Items
            .Select(a => a.TargetRtId.ToString())
            .ToHashSet();

        var updates = new List<AssociationUpdateInfo>();
        foreach (var roleId in roleIds)
        {
            if (!currentRoleIds.Contains(roleId))
            {
                updates.Add(AssociationUpdateInfo.CreateInsert(
                    groupEntityId,
                    new RtEntityId(roleCkTypeId, new OctoObjectId(roleId)),
                    IdentityAssociationConstants.AssignedRoleId));
            }
        }

        if (updates.Count > 0)
        {
            var opResult = new OperationResult();
            await childRepo.ApplyChangesAsync(session, updates, opResult);
        }
    }

    private async Task RunCkModelMigrationsAsync(
        ITenantContext tenantContext,
        IReadOnlyDictionary<string, string>? previousSchemaVersions = null)
    {
        if (ckModelUpgradeService == null)
        {
            return;
        }

        var ckModelIds = new List<CkModelIdVersionRange>
        {
            // System CK model (base model, updated via EnsureSystemCkModelAsync)
            SystemCkIds.CkModelId.ToVersionRange(),
            // Identity and Notification CK models
            SystemIdentityCkIds.CkModelId.ToVersionRange(),
            SystemNotificationCkIds.CkModelId.ToVersionRange()
        };

        logger.LogInformation(
            "Running CK model data migrations for tenant '{TenantId}' with {ModelCount} models",
            tenantContext.TenantId, ckModelIds.Count);

        var result = await ckModelUpgradeService.UpgradeModelsAsync(
            tenantContext.TenantId,
            ckModelIds,
            new CkMigrationOptions { ContinueOnError = false },
            previousSchemaVersions,
            CancellationToken.None);

        if (!result.Success)
        {
            var errorMessage = $"CK model migration failed for tenant '{tenantContext.TenantId}': {string.Join("; ", result.Errors)}";
            logger.LogError("{ErrorMessage}", errorMessage);
            throw new InvalidOperationException(errorMessage);
        }

        if (result.TotalEntitiesAffected > 0)
        {
            logger.LogInformation(
                "CK model data migrations completed for tenant '{TenantId}': {EntitiesAffected} entities affected",
                tenantContext.TenantId, result.TotalEntitiesAffected);
        }
    }
}