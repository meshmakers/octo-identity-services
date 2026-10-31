using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Common.Shared;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>One CK method of the identity service that has a handler (AB#5672).</summary>
/// <param name="MethodId">Qualified method id, always the generated constant of <c>SystemIdentityCkIds</c>.</param>
/// <param name="HandlerType">The handler class.</param>
/// <param name="CarriesSecret">
///     The method has a password or another secret as a parameter or result (<c>sensitive</c> in the CK model). Such a
///     handler is registered only when <see cref="IdentityMethodsOptions.EnablePasswordMethods" /> is on. A test compares this
///     flag with the compiled model, so a later story cannot forget it.
/// </param>
/// <param name="Register">Registers the handler in the method host.</param>
internal sealed record IdentityMethodHandlerRegistration(
    string MethodId,
    Type HandlerType,
    bool CarriesSecret,
    Action<ICkMethodHandlerRegistrationBuilder> Register);

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
        new(SystemIdentityCkIds.UserChangePasswordMethodId, typeof(UserChangePasswordHandler), true,
            b => b.Handle<UserChangePasswordHandler>(SystemIdentityCkIds.UserChangePasswordMethodId)),
        // Role methods carry no password or secret: registered whatever the switch says (AB#7776).
        new(SystemIdentityCkIds.UserSetRolesMethodId, typeof(UserSetRolesHandler), false,
            b => b.Handle<UserSetRolesHandler>(SystemIdentityCkIds.UserSetRolesMethodId)),
        new(SystemIdentityCkIds.UserAddRoleMethodId, typeof(UserAddRoleHandler), false,
            b => b.Handle<UserAddRoleHandler>(SystemIdentityCkIds.UserAddRoleMethodId)),
        new(SystemIdentityCkIds.UserRemoveRoleMethodId, typeof(UserRemoveRoleHandler), false,
            b => b.Handle<UserRemoveRoleHandler>(SystemIdentityCkIds.UserRemoveRoleMethodId)),
        new(SystemIdentityCkIds.UserResetPasswordMethodId, typeof(UserResetPasswordHandler), true,
            b => b.Handle<UserResetPasswordHandler>(SystemIdentityCkIds.UserResetPasswordMethodId)),
        // Group and data-permission methods carry no password or secret either (AB#7779).
        new(SystemIdentityCkIds.GroupAddMemberMethodId, typeof(GroupAddMemberHandler), false,
            b => b.Handle<GroupAddMemberHandler>(SystemIdentityCkIds.GroupAddMemberMethodId)),
        new(SystemIdentityCkIds.GroupRemoveMemberMethodId, typeof(GroupRemoveMemberHandler), false,
            b => b.Handle<GroupRemoveMemberHandler>(SystemIdentityCkIds.GroupRemoveMemberMethodId)),
        new(SystemIdentityCkIds.GroupSetRolesMethodId, typeof(GroupSetRolesHandler), false,
            b => b.Handle<GroupSetRolesHandler>(SystemIdentityCkIds.GroupSetRolesMethodId)),
        new(SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, typeof(DataPermissionGrantToRoleHandler), false,
            b => b.Handle<DataPermissionGrantToRoleHandler>(SystemIdentityCkIds.DataPermissionGrantToRoleMethodId)),
        new(SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId, typeof(DataPermissionRevokeFromRoleHandler), false,
            b => b.Handle<DataPermissionRevokeFromRoleHandler>(SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId))
    ];

    /// <summary>
    ///     The handlers that are registered for this configuration: all without a secret, and those with a secret only when
    ///     <c>Methods:Identity:EnablePasswordMethods</c> is true (production gate of 2026-10-23, default false).
    /// </summary>
    public static IReadOnlyList<IdentityMethodHandlerRegistration> SelectHandlers(IdentityMethodsOptions options) =>
        Handlers.Where(h => !h.CarriesSecret || options.EnablePasswordMethods).ToList();

    /// <summary>Reads the options from the configuration (the host registration runs before the service provider exists).</summary>
    public static IdentityMethodsOptions ReadOptions(IConfiguration configuration) =>
        configuration.GetSection(IdentityMethodsOptions.SectionName).Get<IdentityMethodsOptions>() ??
        new IdentityMethodsOptions();

    /// <summary>
    ///     Registers the method host with the selected handlers: handler registrations, caller token validation against the
    ///     authority of this service, and the tenant binding that the handlers need on the bus. Without a selected handler
    ///     nothing is hosted at all (no queue, no announcement): the gateway then answers <c>METHOD_HANDLER_NOT_AVAILABLE</c>.
    /// </summary>
    /// <returns><c>true</c> when at least one handler is hosted (the caller then adds the discovery consumer to the event hub).</returns>
    public static bool AddIdentityCkMethodHost(this IServiceCollection services,
        IReadOnlyList<IdentityMethodHandlerRegistration> selected)
    {
        services.AddOptions<IdentityMethodsOptions>().BindConfiguration(IdentityMethodsOptions.SectionName);
        if (selected.Count == 0)
        {
            return false;
        }

        services.AddCkMethodHandlers(ServiceName, builder =>
        {
            foreach (var handler in selected)
            {
                handler.Register(builder);
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
