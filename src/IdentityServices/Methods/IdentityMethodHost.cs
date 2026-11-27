using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Common.Shared;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using static Meshmakers.Octo.Backend.IdentityServices.Methods.IdentityMethodHandlerRegistration;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>One CK method of the identity service that has a handler (AB#5672).</summary>
/// <param name="MethodId">Qualified method id, always the generated constant of <c>SystemIdentityCkIds</c>.</param>
/// <param name="HandlerType">The handler class.</param>
/// <param name="CarriesSecret">
///     The method has a password or another secret as a parameter or result (<c>sensitive</c> in the CK model). Such a
///     handler is offered on the bus only when <see cref="IdentityMethodsOptions.EnablePasswordMethods" /> is on. A test
///     compares this flag with the compiled model, so a later story cannot forget it.
/// </param>
/// <param name="ServesRestFacade">
///     A REST endpoint of this service is a facade of the method and must keep working while the switch keeps the method off
///     the bus (AB#8413): with the switch off such a secret-carrying handler is registered <b>local only</b>
///     (<see cref="RegisterLocalOnly" />: not announced, no queue, only this process calls it), so the password reaches the
///     handler in-process and never the broker.
/// </param>
/// <param name="Register">Registers the handler for the bus (announced, queue) and for in-process calls.</param>
/// <param name="RegisterLocalOnly">Registers the handler local only (<c>HandleLocalOnly</c>, AB#8411).</param>
internal sealed record IdentityMethodHandlerRegistration(
    string MethodId,
    Type HandlerType,
    bool CarriesSecret,
    bool ServesRestFacade,
    Action<ICkMethodHandlerRegistrationBuilder> Register,
    Action<ICkMethodHandlerRegistrationBuilder> RegisterLocalOnly)
{
    /// <summary>One row of <see cref="IdentityMethodHost.Handlers" />: both registration forms from the handler type.</summary>
    public static IdentityMethodHandlerRegistration For<THandler>(string methodId, bool carriesSecret,
        bool servesRestFacade = false) where THandler : class, ICkMethodHandler =>
        new(methodId, typeof(THandler), carriesSecret, servesRestFacade, b => b.Handle<THandler>(methodId),
            b => b.HandleLocalOnly<THandler>(methodId));
}

/// <summary>
///     The one place that hosts CK methods in the identity service (AB#5672). A later story adds a handler class and one row
///     to <see cref="Handlers" />; nothing else changes (host, caller token validation and the secret gate are set up here).
/// </summary>
internal static class IdentityMethodHost
{
    /// <summary>Name of this service in the method handler registry.</summary>
    public const string ServiceName = "IdentityService";

    /// <summary>All handlers of the identity service; the switch decides which of them are registered.</summary>
    public static IReadOnlyList<IdentityMethodHandlerRegistration> Handlers { get; } =
    [
        // The account pages' POST api/manage/change-password and set-password are their facades (AB#8414): local only while
        // the switch is off.
        For<UserChangePasswordHandler>(SystemIdentityCkIds.UserChangePasswordMethodId, true, servesRestFacade: true),
        For<UserSetPasswordHandler>(SystemIdentityCkIds.UserSetPasswordMethodId, true, servesRestFacade: true),
        // Role methods carry no password or secret: registered whatever the switch says (AB#7776).
        For<UserSetRolesHandler>(SystemIdentityCkIds.UserSetRolesMethodId, false),
        For<UserAddRoleHandler>(SystemIdentityCkIds.UserAddRoleMethodId, false),
        For<UserRemoveRoleHandler>(SystemIdentityCkIds.UserRemoveRoleMethodId, false),
        // REST POST users/ResetPassword is its facade (AB#8413): local only while the switch is off.
        For<UserResetPasswordHandler>(SystemIdentityCkIds.UserResetPasswordMethodId, true, servesRestFacade: true),
        For<UserDisableTwoFactorHandler>(SystemIdentityCkIds.UserDisableTwoFactorMethodId, false),
        // Merge carries no password or secret: registered whatever the switch says (AB#7778).
        For<UserMergeHandler>(SystemIdentityCkIds.UserMergeMethodId, false),
        // The static create carries the optional, sensitive initial password: gated like the password methods (AB#7777).
        // REST POST users is its facade (AB#8413): local only while the switch is off.
        For<UserCreateUserHandler>(SystemIdentityCkIds.UserCreateUserMethodId, true, servesRestFacade: true),
        // Group and data-permission methods carry no password or secret either (AB#7779).
        For<GroupAddMemberHandler>(SystemIdentityCkIds.GroupAddMemberMethodId, false),
        For<GroupRemoveMemberHandler>(SystemIdentityCkIds.GroupRemoveMemberMethodId, false),
        For<GroupSetRolesHandler>(SystemIdentityCkIds.GroupSetRolesMethodId, false),
        // Nested groups (System.Identity 3.3.0): REST PUT/DELETE groups/{group}/members/groups/{child} are their facades.
        For<GroupAddChildGroupHandler>(SystemIdentityCkIds.GroupAddChildGroupMethodId, false),
        For<GroupRemoveChildGroupHandler>(SystemIdentityCkIds.GroupRemoveChildGroupMethodId, false),
        // Client roles and overlay URIs (System.Identity 3.3.0) carry no secret: registered whatever the switch says. The
        // REST role and overlay endpoints of ClientsController are their facades.
        For<ClientSetRolesHandler>(SystemIdentityCkIds.ClientSetRolesMethodId, false),
        For<ClientAddRoleHandler>(SystemIdentityCkIds.ClientAddRoleMethodId, false),
        For<ClientRemoveRoleHandler>(SystemIdentityCkIds.ClientRemoveRoleMethodId, false),
        For<ClientApplyOverlayUrisHandler>(SystemIdentityCkIds.ClientApplyOverlayUrisMethodId, false),
        For<ClientCleanOverlayEntriesHandler>(SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId, false),
        For<DataPermissionGrantToRoleHandler>(SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, false),
        For<DataPermissionRevokeFromRoleHandler>(SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId, false),
        // System.Identity 3.4.0: REST PUT dataPermissions/policies/{policyRtId}/enforcementMode is its facade.
        For<DataPolicySetEnforcementModeHandler>(SystemIdentityCkIds.DataPolicySetEnforcementModeMethodId, false),
        // Secret methods carry a secret (sensitive result / parameter): gated like the password methods. The REST
        // secret write endpoints of ApiSecretsController are their facades: local only while the switch is off.
        For<ClientAddSecretHandler>(SystemIdentityCkIds.ClientAddSecretMethodId, true, servesRestFacade: true),
        For<ClientRemoveSecretHandler>(SystemIdentityCkIds.ClientRemoveSecretMethodId, true, servesRestFacade: true),
        For<ClientUpdateSecretHandler>(SystemIdentityCkIds.ClientUpdateSecretMethodId, true, servesRestFacade: true),
        For<ApiResourceAddSecretHandler>(SystemIdentityCkIds.ApiResourceAddSecretMethodId, true, servesRestFacade: true),
        For<ApiResourceRemoveSecretHandler>(SystemIdentityCkIds.ApiResourceRemoveSecretMethodId, true,
            servesRestFacade: true),
        For<ApiResourceUpdateSecretHandler>(SystemIdentityCkIds.ApiResourceUpdateSecretMethodId, true,
            servesRestFacade: true),
        // System.Identity 3.5.0: client mirrors. The REST endpoints of ClientMirrorController and
        // ClientAutoProvisionFlagController are their facades. Only the rotation carries a secret (its result): gated like the
        // secret methods, local only for its facade while the switch is off.
        For<ClientProvisionMirrorsHandler>(SystemIdentityCkIds.ClientProvisionMirrorsMethodId, false),
        For<ClientProvisionMirrorInTenantHandler>(SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId, false),
        For<ClientRotateMirrorSecretHandler>(SystemIdentityCkIds.ClientRotateMirrorSecretMethodId, true,
            servesRestFacade: true),
        For<ClientRemoveMirrorHandler>(SystemIdentityCkIds.ClientRemoveMirrorMethodId, false),
        For<ClientSetMirrorAutoProvisionHandler>(SystemIdentityCkIds.ClientSetMirrorAutoProvisionMethodId, false),
        // System.Identity 3.9.0 (AB#9923): the mirror role list; no secret, no REST facade.
        For<ClientSetMirrorRolesHandler>(SystemIdentityCkIds.ClientSetMirrorRolesMethodId, false),
        // System.Identity 3.5.0: admin provisioning (AdminProvisioningController) and the mapping create
        // (ExternalTenantUserMappingsController) as static methods; no secret.
        For<ExternalTenantUserMappingProvisionAdminHandler>(
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId, false),
        For<ExternalTenantUserMappingProvisionAdminWithGroupsHandler>(
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminWithGroupsMethodId, false),
        For<ExternalTenantUserMappingProvisionCurrentUserHandler>(
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId, false),
        For<ExternalTenantUserMappingRemoveAdminProvisioningHandler>(
            SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId, false),
        For<ExternalTenantUserMappingCreateMappingHandler>(
            SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId, false),
        // System.Identity 3.7.0: create, update and delete of roles, groups, API scopes and API resources; the REST CRUD
        // endpoints of RolesController, GroupsController, ApiScopesController and ApiResourcesController are their facades.
        // No secret (API resource secrets change only through the secret methods).
        For<RoleCreateRoleHandler>(SystemIdentityCkIds.RoleCreateRoleMethodId, false),
        For<RoleUpdateRoleHandler>(SystemIdentityCkIds.RoleUpdateRoleMethodId, false),
        For<RoleDeleteRoleHandler>(SystemIdentityCkIds.RoleDeleteRoleMethodId, false),
        For<GroupCreateGroupHandler>(SystemIdentityCkIds.GroupCreateGroupMethodId, false),
        For<GroupUpdateGroupHandler>(SystemIdentityCkIds.GroupUpdateGroupMethodId, false),
        For<GroupDeleteGroupHandler>(SystemIdentityCkIds.GroupDeleteGroupMethodId, false),
        For<ApiScopeCreateApiScopeHandler>(SystemIdentityCkIds.ApiScopeCreateApiScopeMethodId, false),
        For<ApiScopeUpdateApiScopeHandler>(SystemIdentityCkIds.ApiScopeUpdateApiScopeMethodId, false),
        For<ApiScopeDeleteApiScopeHandler>(SystemIdentityCkIds.ApiScopeDeleteApiScopeMethodId, false),
        For<ApiResourceCreateApiResourceHandler>(SystemIdentityCkIds.ApiResourceCreateApiResourceMethodId, false),
        For<ApiResourceUpdateApiResourceHandler>(SystemIdentityCkIds.ApiResourceUpdateApiResourceMethodId, false),
        For<ApiResourceDeleteApiResourceHandler>(SystemIdentityCkIds.ApiResourceDeleteApiResourceMethodId, false),
        // System.Identity 3.8.0: create, update and delete of identity providers, e-mail domain group rules, data permissions
        // and policies, clients, and the update and delete of external tenant user mappings; the REST CRUD endpoints of
        // IdentityProvidersController, EmailDomainGroupRulesController, DataPermissionsController, ClientsController and
        // ExternalTenantUserMappingsController are their facades. The provider create/update and the client create/update
        // carry a client secret (sensitive parameter): gated like the secret methods, local only for their facades while the
        // switch is off.
        For<IdentityProviderCreateIdentityProviderHandler>(SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId,
            true, servesRestFacade: true),
        For<IdentityProviderUpdateIdentityProviderHandler>(SystemIdentityCkIds.IdentityProviderUpdateIdentityProviderMethodId,
            true, servesRestFacade: true),
        For<IdentityProviderDeleteIdentityProviderHandler>(SystemIdentityCkIds.IdentityProviderDeleteIdentityProviderMethodId,
            false),
        For<EmailDomainGroupRuleCreateHandler>(SystemIdentityCkIds.EmailDomainGroupRuleCreateEmailDomainGroupRuleMethodId,
            false),
        For<EmailDomainGroupRuleUpdateHandler>(SystemIdentityCkIds.EmailDomainGroupRuleUpdateEmailDomainGroupRuleMethodId,
            false),
        For<EmailDomainGroupRuleDeleteHandler>(SystemIdentityCkIds.EmailDomainGroupRuleDeleteEmailDomainGroupRuleMethodId,
            false),
        For<ExternalTenantUserMappingUpdateMappingHandler>(SystemIdentityCkIds.ExternalTenantUserMappingUpdateMappingMethodId,
            false),
        For<ExternalTenantUserMappingDeleteMappingHandler>(SystemIdentityCkIds.ExternalTenantUserMappingDeleteMappingMethodId,
            false),
        For<DataPermissionCreateDataPermissionHandler>(SystemIdentityCkIds.DataPermissionCreateDataPermissionMethodId, false),
        For<DataPermissionDeleteDataPermissionHandler>(SystemIdentityCkIds.DataPermissionDeleteDataPermissionMethodId, false),
        For<DataPermissionCreatePolicyHandler>(SystemIdentityCkIds.DataPermissionCreatePolicyMethodId, false),
        For<DataPolicyDeleteDataPolicyHandler>(SystemIdentityCkIds.DataPolicyDeleteDataPolicyMethodId, false),
        For<ClientCreateClientHandler>(SystemIdentityCkIds.ClientCreateClientMethodId, true, servesRestFacade: true),
        For<ClientUpdateClientHandler>(SystemIdentityCkIds.ClientUpdateClientMethodId, true, servesRestFacade: true),
        For<ClientDeleteClientHandler>(SystemIdentityCkIds.ClientDeleteClientMethodId, false)
    ];

    /// <summary>
    ///     The handlers offered on the bus for this configuration (announced, with a queue): all without a secret, and those
    ///     with a secret only when <c>Methods:Identity:EnablePasswordMethods</c> is true (production gate of 2026-10-23,
    ///     default false). This process calls them in-process as well.
    /// </summary>
    public static IReadOnlyList<IdentityMethodHandlerRegistration> SelectHandlers(IdentityMethodsOptions options) =>
        Handlers.Where(h => !h.CarriesSecret || options.EnablePasswordMethods).ToList();

    /// <summary>
    ///     The handlers registered <b>local only</b> for this configuration (AB#8413): with the switch off, the secret-carrying
    ///     handlers that a REST facade of this service calls (<see cref="IdentityMethodHandlerRegistration.ServesRestFacade" />).
    ///     They are not announced and have no queue, so another service (the GraphQL gateway) still gets
    ///     <c>METHOD_HANDLER_NOT_AVAILABLE</c> and no password reaches the broker. Empty when the switch is on (then
    ///     <see cref="SelectHandlers" /> offers them on the bus).
    /// </summary>
    public static IReadOnlyList<IdentityMethodHandlerRegistration> SelectLocalOnlyHandlers(IdentityMethodsOptions options) =>
        options.EnablePasswordMethods
            ? []
            : Handlers.Where(h => h.CarriesSecret && h.ServesRestFacade).ToList();

    /// <summary>Reads the options from the configuration (the host registration runs before the service provider exists).</summary>
    public static IdentityMethodsOptions ReadOptions(IConfiguration configuration) =>
        configuration.GetSection(IdentityMethodsOptions.SectionName).Get<IdentityMethodsOptions>() ??
        new IdentityMethodsOptions();

    /// <summary>
    ///     Registers the method host with the selected handlers: bus handlers (<paramref name="selected" />), local-only
    ///     handlers (<paramref name="localOnly" />, AB#8413), caller token validation against the authority of this service, and
    ///     the tenant binding that the handlers need. Without any handler nothing is hosted at all (no queue, no announcement):
    ///     the gateway then answers <c>METHOD_HANDLER_NOT_AVAILABLE</c>.
    /// </summary>
    /// <returns><c>true</c> when at least one handler is hosted.</returns>
    public static bool AddIdentityCkMethodHost(this IServiceCollection services,
        IReadOnlyList<IdentityMethodHandlerRegistration> selected,
        IReadOnlyList<IdentityMethodHandlerRegistration>? localOnly = null)
    {
        localOnly ??= [];
        services.AddOptions<IdentityMethodsOptions>().BindConfiguration(IdentityMethodsOptions.SectionName);

        // AB#8412: the REST facades of UsersController call the methods through the dispatcher; a method this service
        // hosts runs in-process (AB#8411), nothing is sent to the broker. Program.cs adds the registry feed to the event hub.
        services.AddCkMethodDispatcher();
        services.TryAddScoped<IIdentityMethodFacade, IdentityMethodFacade>();
        if (selected.Count == 0 && localOnly.Count == 0)
        {
            return false;
        }

        services.AddCkMethodHandlers(ServiceName, builder =>
        {
            foreach (var handler in selected)
            {
                handler.Register(builder);
            }

            // AB#8413: not announced, no queue - only the REST facades of this process call them (password in-process only).
            foreach (var handler in localOnly)
            {
                handler.RegisterLocalOnly(builder);
            }
        });

        // The bus is internal but not authenticated per message: the host validates the access token the caller forwarded
        // (issuer, signature, expiry, tenant, scope) with the same authority the HTTP API of this service uses.
        services.AddCkMethodCallerTokenValidation();
        services.AddOptions<CkMethodTokenOptions>()
            .Configure<IOptions<OctoIdentityServicesOptions>, IWebHostEnvironment>((token, identity, environment) =>
            {
                if (string.IsNullOrWhiteSpace(token.Authority) && string.IsNullOrWhiteSpace(token.MetadataAddress))
                {
                    var authority = identity.Value.AuthorityUrl.EnsureEndsWith("/");
                    token.Authority = authority;
                    token.ValidIssuer ??= authority;
                }

                if (environment.IsDevelopment())
                {
                    token.RequireHttpsMetadata = false;
                }
            });
        // Development: the authority is the local self-signed https endpoint (like ConfigureJwtBearerOptions).
        services.AddHttpClient(CkMethodTokenOptions.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp =>
            {
                var handler = new HttpClientHandler();
                if (sp.GetRequiredService<IWebHostEnvironment>().IsDevelopment())
                {
                    handler.ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                }

                return handler;
            });

        // A handler runs on the bus without an HTTP request; the tenant of the invocation is bound per scope.
        services.TryAddScoped<IMethodTenantAccessor, MethodTenantAccessor>();
        services.TryAddScoped<IIdentityMethodAuditWriter, IdentityMethodAuditWriter>();
        ReplaceTenantResolver(services);
        return true;
    }

    private static void ReplaceTenantResolver(IServiceCollection services)
    {
        services.RemoveAll<IMultiTenancyResolverService>();
        services.AddScoped<MultiTenancyResolverService>();
        services.AddScoped<IMultiTenancyResolverService, MethodTenantResolverService>();
    }
}
