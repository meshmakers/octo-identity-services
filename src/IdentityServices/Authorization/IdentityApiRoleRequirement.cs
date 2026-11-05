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
/// <param name="WarnFallbackRoles">
///     AB#5861: roles that still pass while <see cref="IdentityApiAuthorizationOptions.SecretManagementRoleEnforcement" />
///     (or the cluster-wide <see cref="IdentityApiAuthorizationOptions.RoleEnforcement" />) is <c>Warn</c> — the rule
///     before the requirement was tightened. Every such call is logged. <c>null</c> = the requirement is not staged.
/// </param>
public sealed record IdentityApiRoleRequirement(
    IReadOnlyList<string> Roles,
    bool SystemTenantOnly = false,
    IReadOnlyList<string>? WarnFallbackRoles = null)
    : IAuthorizationRequirement
{
    /// <summary>
    ///     Decides a staged requirement for a caller (shared by the REST handler, the client controller and the client
    ///     secret methods, so the three paths cannot drift). The cluster-wide <c>Warn</c> that lets every caller through is
    ///     not part of it; the REST handler applies it on top.
    /// </summary>
    internal IdentityApiRoleDecision Decide(Func<string, bool> hasRole, IdentityApiAuthorizationOptions options)
    {
        if (Roles.Any(hasRole))
        {
            return IdentityApiRoleDecision.Allowed;
        }

        var staged = options.SecretManagementRoleEnforcement == IdentityApiRoleEnforcementMode.Warn ||
                     options.RoleEnforcement == IdentityApiRoleEnforcementMode.Warn;
        return WarnFallbackRoles != null && staged && WarnFallbackRoles.Any(hasRole)
            ? IdentityApiRoleDecision.AllowedByStagedWarn
            : IdentityApiRoleDecision.Denied;
    }

    /// <summary>
    ///     The reason of a refusal, in the AB#5227 shape (the 403 body <c>{"message": "..."}</c> the frontends show): names
    ///     the missing role so the caller knows what to ask for.
    /// </summary>
    internal string DeniedMessage()
    {
        if (SystemTenantOnly)
        {
            return "Access is denied: this operation is only available in the system tenant.";
        }

        var roles = Roles.Count == 1
            ? $"the role '{Roles[0]}'"
            : "one of the roles " + string.Join(", ", Roles.Select(r => $"'{r}'"));
        return $"Access is denied: this operation requires {roles} in the tenant. " +
               "The token carries no such role; ask a tenant administrator to grant it.";
    }
}

/// <summary>Outcome of <see cref="IdentityApiRoleRequirement.Decide" />.</summary>
public enum IdentityApiRoleDecision
{
    /// <summary>The caller holds one of the required roles.</summary>
    Allowed,

    /// <summary>The caller holds only a fallback role and the staged switch is <c>Warn</c>: let through, logged.</summary>
    AllowedByStagedWarn,

    /// <summary>Refused (unless the cluster-wide <c>Warn</c> applies, REST only).</summary>
    Denied
}

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
            context.Fail(new AuthorizationFailureReason(this, requirement.DeniedMessage()));
            return Task.CompletedTask;
        }

        var currentOptions = options.CurrentValue;
        var decision = requirement.Decide(role => HasTenantRole(context.User, role), currentOptions);
        if (decision == IdentityApiRoleDecision.Allowed)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var subject = context.User.FindFirst(JwtClaimTypes.Subject)?.Value;
        var clientId = context.User.FindFirst(JwtClaimTypes.ClientId)?.Value;
        var requiredRoles = string.Join(",", requirement.Roles);

        if (decision == IdentityApiRoleDecision.AllowedByStagedWarn)
        {
            // AB#5861: the caller holds the previous roles only. This line is the inventory the rollout precheck reads.
            logger.LogWarning(
                "Identity API call without required role allowed by SecretManagementRoleEnforcement=Warn: {Method} {Path} in tenant {TenantId} by subject {Subject} / client {ClientId}, required any of [{RequiredRoles}]. " +
                "This would be denied with SecretManagementRoleEnforcement=Enforce (AB#5861)",
                httpContext?.Request.Method, httpContext?.Request.Path.Value, tenantId, subject, clientId,
                requiredRoles);
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        if (currentOptions.RoleEnforcement == IdentityApiRoleEnforcementMode.Warn)
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
        // AB#5861: the reason goes into the 403 body (IdentityApiForbiddenReasonResultHandler, AB#5227 shape).
        context.Fail(new AuthorizationFailureReason(this, requirement.DeniedMessage()));
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
