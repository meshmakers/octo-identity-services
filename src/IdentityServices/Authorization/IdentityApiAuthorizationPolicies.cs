using IdentityServerPersistence;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization;

/// <summary>
///     The authorization policies of the identity tenant REST API, in one place so the host and the tests
///     use the very same definitions (AB#5859).
/// </summary>
/// <remarks>
///     <para>
///         Before AB#5859 the API only checked the scope (<c>octo_api.full_access</c> /
///         <c>octo_api.read_only</c>), which every interactive client requests — so every signed-in user of
///         a tenant could administer its identity. The administration policies now also require a tenant
///         role, the same rule as the GraphQL side (built-in data policy <c>IdentityAdministrationPolicy</c>
///         grants the identity entities to <c>UserManagement</c>).
///     </para>
///     <list type="bullet">
///         <item>
///             <c>UserManagement</c>: users, roles, groups, external tenant user mappings, e-mail
///             identifier bindings and data permissions.
///         </item>
///         <item>
///             <c>TenantManagement</c> or <c>UserManagement</c>: clients, client mirrors, API resources,
///             API scopes, API secrets, identity providers, e-mail domain group rules and cross-tenant
///             admin provisioning (the Studio guards those pages with either role).
///         </item>
///         <item>
///             Directory reads (role names, a client's roles and actors): additionally
///             <c>AdminPanelManagement</c> or <c>CommunicationManagement</c>.
///         </item>
///         <item>
///             Log level: <c>TenantManagement</c> in the system tenant only.
///         </item>
///     </list>
///     <para>
///         The plain scope policies (<see cref="IdentityServiceConstants.IdentityApiReadOnlyPolicy" />,
///         <see cref="IdentityServiceConstants.IdentityApiReadWritePolicy" />) remain for endpoints that are
///         open to every signed-in user of the tenant (password generator).
///     </para>
/// </remarks>
internal static class IdentityApiAuthorizationPolicies
{
    /// <summary>
    ///     Roles that may administer users, roles, groups, mappings and data permissions.
    /// </summary>
    internal static readonly IReadOnlyList<string> UserAdministrationRoles = [CommonConstants.UserManagementRole];

    /// <summary>
    ///     Roles that may administer clients, API resources/scopes/secrets and identity providers.
    /// </summary>
    internal static readonly IReadOnlyList<string> TenantAdministrationRoles =
        [CommonConstants.TenantManagementRole, CommonConstants.UserManagementRole];

    /// <summary>
    ///     Roles that may read role names and a client's roles/actors — the service-account panels of the
    ///     Studio (settings, adapter detail, data-flow editor) and the communication controller's
    ///     <c>IdentityClientReader</c>, which forwards the caller's token.
    /// </summary>
    internal static readonly IReadOnlyList<string> DirectoryReadRoles =
    [
        CommonConstants.UserManagementRole, CommonConstants.TenantManagementRole,
        CommonConstants.AdminPanelManagementRole, CommonConstants.CommunicationManagementRole
    ];

    /// <summary>
    ///     Roles that may run service-wide operations (log level) — only in the system tenant.
    /// </summary>
    internal static readonly IReadOnlyList<string> ServiceAdministrationRoles = [CommonConstants.TenantManagementRole];

    /// <summary>
    ///     Registers the policies.
    /// </summary>
    public static void AddIdentityApiPolicies(this AuthorizationOptions options)
    {
        options.AddPolicy(IdentityServiceConstants.IdentityApiReadOnlyPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                CommonConstants.OctoApiFullAccess,
                CommonConstants.OctoApiReadOnly));

        options.AddPolicy(IdentityServiceConstants.IdentityApiReadWritePolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                CommonConstants.OctoApiFullAccess));

        options.AddPolicy(IdentityServiceConstants.IdentityUserAdministrationReadPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess,
                    CommonConstants.OctoApiReadOnly)
                .AddRequirements(new IdentityApiRoleRequirement(UserAdministrationRoles)));

        options.AddPolicy(IdentityServiceConstants.IdentityUserAdministrationWritePolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess)
                .AddRequirements(new IdentityApiRoleRequirement(UserAdministrationRoles)));

        options.AddPolicy(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess,
                    CommonConstants.OctoApiReadOnly)
                .AddRequirements(new IdentityApiRoleRequirement(TenantAdministrationRoles)));

        options.AddPolicy(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess)
                .AddRequirements(new IdentityApiRoleRequirement(TenantAdministrationRoles)));

        options.AddPolicy(IdentityServiceConstants.IdentityDirectoryReadPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess,
                    CommonConstants.OctoApiReadOnly)
                .AddRequirements(new IdentityApiRoleRequirement(DirectoryReadRoles)));

        options.AddPolicy(IdentityServiceConstants.IdentityServiceAdministrationPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess)
                .AddRequirements(new IdentityApiRoleRequirement(ServiceAdministrationRoles, SystemTenantOnly: true)));
    }
}
