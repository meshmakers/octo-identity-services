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
///             API scopes, reading API secret metadata, identity providers, e-mail domain group rules and
///             cross-tenant admin provisioning (the Studio guards those pages with either role).
///         </item>
///         <item>
///             <c>SecretManagement</c> (AB#5861, <see cref="IdentityServiceConstants.IdentitySecretAdministrationPolicy" />):
///             creating, rotating and deleting API secrets of clients and API resources, and setting a client
///             secret on client create/update. Staged by
///             <see cref="IdentityApiAuthorizationOptions.SecretManagementRoleEnforcement" />: in <c>Warn</c> (default)
///             <c>TenantManagement</c> or <c>UserManagement</c> still pass and are logged. Only a direct or
///             group-inherited <c>SecretManagement</c> in the token counts; membership in <c>TenantOwners</c> alone does
///             not carry it (the group holds no such role on purpose, AB#5544).
///         </item>
///         <item>
///             Directory reads (role names, a client's roles and actors): additionally
///             <c>AdminPanelManagement</c> or <c>CommunicationManagement</c>.
///         </item>
///         <item>
///             Log level: <c>TenantManagement</c> in the system tenant only.
///         </item>
///         <item>
///             User directory (<c>users/directory</c>: id and display name only): no role, but the token
///             must have been issued for the route tenant (<see cref="IdentityApiOwnTenantRequirement" />).
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
    ///     AB#5861: the role that may create, rotate and delete API secrets.
    /// </summary>
    internal static readonly IReadOnlyList<string> SecretAdministrationRoles = [CommonConstants.SecretManagementRole];

    /// <summary>
    ///     AB#5861: the shared requirement of every API secret write (REST policy, client create/update with a secret,
    ///     client secret methods). While <see cref="IdentityApiAuthorizationOptions.SecretManagementRoleEnforcement" /> is
    ///     <c>Warn</c>, the previous rule (<see cref="TenantAdministrationRoles" />) still passes and is logged.
    /// </summary>
    internal static readonly IdentityApiRoleRequirement SecretAdministrationRequirement =
        new(SecretAdministrationRoles, WarnFallbackRoles: TenantAdministrationRoles);

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

        options.AddPolicy(IdentityServiceConstants.IdentitySecretAdministrationPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess)
                .AddRequirements(SecretAdministrationRequirement));

        options.AddPolicy(IdentityServiceConstants.IdentityDirectoryReadPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess,
                    CommonConstants.OctoApiReadOnly)
                .AddRequirements(new IdentityApiRoleRequirement(DirectoryReadRoles)));

        // The slim user directory (id + display name) has no role on purpose — every user of the tenant
        // may pick a colleague (assignee pickers). The own-tenant requirement replaces the role as the
        // gate that keeps foreign tokens out.
        options.AddPolicy(IdentityServiceConstants.IdentityUserDirectoryReadPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess,
                    CommonConstants.OctoApiReadOnly)
                .AddRequirements(new IdentityApiOwnTenantRequirement()));

        options.AddPolicy(IdentityServiceConstants.IdentityServiceAdministrationPolicy, policyBuilder =>
            policyBuilder.RequireClaim(InfrastructureCommon.ClaimScope,
                    CommonConstants.OctoApiFullAccess)
                .AddRequirements(new IdentityApiRoleRequirement(ServiceAdministrationRoles, SystemTenantOnly: true)));
    }
}
