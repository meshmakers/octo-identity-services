using System.Security.Claims;
using Duende.IdentityModel;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization;

/// <summary>
///     The caller must hold at least one of <see cref="Roles" /> as a tenant role (AB#5859).
/// </summary>
/// <param name="Roles">Any of these tenant roles satisfies the requirement.</param>
/// <param name="SystemTenantOnly">
///     The route tenant must also be the system tenant (service-wide operations such as the log level).
/// </param>
public sealed record IdentityApiRoleRequirement(IReadOnlyList<string> Roles, bool SystemTenantOnly = false)
    : IAuthorizationRequirement;

/// <summary>
///     Evaluates <see cref="IdentityApiRoleRequirement" /> against the role claims of the token.
/// </summary>
/// <remarks>
///     <para>
///         Roles arrive as one <c>role</c> claim per role name: user tokens carry the effective tenant
///         roles of the user, client-credentials tokens the effective roles of the client (direct and
///         group-inherited, AB#4183). The identity service disables the inbound claim mapping
///         (<c>MapInboundClaims = false</c>), but the identity's <c>RoleClaimType</c> stays
///         <see cref="ClaimTypes.Role" /> — so <c>IsInRole</c> alone answers <c>false</c> for every real
///         token (the RoleClaimType mismatch of AB#4969 / AB#5539). The check therefore probes both
///         spellings, the platform convention of the bot service, MCP service and asset repository.
///     </para>
///     <para>
///         The same role rule as the GraphQL side: the built-in data policy
///         <c>IdentityAdministrationPolicy</c> grants the identity entities only to <c>UserManagement</c>.
///     </para>
///     <para>
///         <see cref="IdentityApiRoleEnforcementMode.Warn" /> lets a caller without the role through and
///         logs a warning, so callers that still need a role can be found before switching to
///         <see cref="IdentityApiRoleEnforcementMode.Enforce" />.
///     </para>
/// </remarks>
internal sealed class IdentityApiRoleAuthorizationHandler(
    IOptionsMonitor<IdentityApiAuthorizationOptions> options,
    IOptions<OctoSystemConfiguration> systemConfiguration,
    ILogger<IdentityApiRoleAuthorizationHandler> logger) : AuthorizationHandler<IdentityApiRoleRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        IdentityApiRoleRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            // Unauthenticated requests are answered 401 by the authentication layer.
            return Task.CompletedTask;
        }

        var httpContext = context.Resource as HttpContext;
        var tenantId = httpContext?.GetRouteValue("tenantId") as string;

        if (requirement.SystemTenantOnly && !string.Equals(tenantId?.Trim(),
                systemConfiguration.Value.SystemTenantId.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            // Not subject to the Warn mode: a service-wide operation from a customer tenant is never legitimate.
            logger.LogWarning(
                "Identity API call denied, system-tenant-only operation called in tenant {TenantId}: {Method} {Path} (AB#5859)",
                tenantId, httpContext?.Request.Method, httpContext?.Request.Path.Value);
            return Task.CompletedTask;
        }

        if (requirement.Roles.Any(role => HasTenantRole(context.User, role)))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var subject = context.User.FindFirst(JwtClaimTypes.Subject)?.Value;
        var clientId = context.User.FindFirst(JwtClaimTypes.ClientId)?.Value;
        var requiredRoles = string.Join(",", requirement.Roles);

        if (options.CurrentValue.RoleEnforcement == IdentityApiRoleEnforcementMode.Warn)
        {
            logger.LogWarning(
                "Identity API call without required role allowed by RoleEnforcement=Warn: {Method} {Path} in tenant {TenantId} by subject {Subject} / client {ClientId}, required any of [{RequiredRoles}]. " +
                "This would be denied with RoleEnforcement=Enforce (AB#5859)",
                httpContext?.Request.Method, httpContext?.Request.Path.Value, tenantId, subject, clientId,
                requiredRoles);
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        logger.LogWarning(
            "Identity API call denied, required role missing: {Method} {Path} in tenant {TenantId} by subject {Subject} / client {ClientId}, required any of [{RequiredRoles}] (AB#5859)",
            httpContext?.Request.Method, httpContext?.Request.Path.Value, tenantId, subject, clientId,
            requiredRoles);
        return Task.CompletedTask;
    }

    /// <summary>
    ///     Whether the principal carries the tenant role under the identity's role claim type, the raw
    ///     JWT <c>role</c> claim or the inbound-mapped <see cref="ClaimTypes.Role" /> claim.
    /// </summary>
    internal static bool HasTenantRole(ClaimsPrincipal principal, string roleName)
    {
        return principal.IsInRole(roleName) ||
               principal.Claims.Any(c =>
                   (c.Type == JwtClaimTypes.Role || c.Type == ClaimTypes.Role) &&
                   string.Equals(c.Value, roleName, StringComparison.Ordinal));
    }
}
