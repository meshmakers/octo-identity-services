using Duende.IdentityModel;
using Microsoft.AspNetCore.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization;

/// <summary>
///     The token must have been issued for the route tenant (AB#5859).
/// </summary>
/// <remarks>
///     <para>
///         Used by endpoints that need no tenant role (the slim user directory) and therefore must not
///         rely on the role check to keep foreign tokens out. The platform's
///         <c>TenantAuthorizationMiddleware</c> already compares the route tenant with <c>tenant_id</c>, but
///         its modes are operator-configurable (<c>UserTokenEnforcement=LogOnly</c>,
///         <c>ServiceTokenEnforcement=Warn|Disabled</c>, the cross-tenant service-client allow list, the
///         parent-tenant administration rule). This requirement is unconditional: no Warn mode, no
///         allow list, no parent-tenant rule, no token without <c>tenant_id</c> — for user and
///         client-credentials tokens alike.
///     </para>
/// </remarks>
public sealed class IdentityApiOwnTenantRequirement : IAuthorizationRequirement
{
    internal const string TenantIdClaimType = "tenant_id";
}

/// <summary>
///     Evaluates <see cref="IdentityApiOwnTenantRequirement" />.
/// </summary>
internal sealed class IdentityApiOwnTenantAuthorizationHandler(
    ILogger<IdentityApiOwnTenantAuthorizationHandler> logger) : AuthorizationHandler<IdentityApiOwnTenantRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        IdentityApiOwnTenantRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            // Unauthenticated requests are answered 401 by the authentication layer.
            return Task.CompletedTask;
        }

        var httpContext = context.Resource as HttpContext;
        var routeTenantId = (httpContext?.GetRouteValue("tenantId") as string)?.Trim();
        var tokenTenantId = context.User.FindFirst(IdentityApiOwnTenantRequirement.TenantIdClaimType)?.Value.Trim();

        if (!string.IsNullOrEmpty(routeTenantId) && !string.IsNullOrEmpty(tokenTenantId) &&
            string.Equals(routeTenantId, tokenTenantId, StringComparison.OrdinalIgnoreCase))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        logger.LogWarning(
            "Identity API call denied, token tenant {TokenTenantId} does not match route tenant {RouteTenantId}: {Method} {Path} by subject {Subject} / client {ClientId} (AB#5859)",
            string.IsNullOrEmpty(tokenTenantId) ? "<none>" : tokenTenantId, routeTenantId,
            httpContext?.Request.Method, httpContext?.Request.Path.Value,
            context.User.FindFirst(JwtClaimTypes.Subject)?.Value,
            context.User.FindFirst(JwtClaimTypes.ClientId)?.Value);
        return Task.CompletedTask;
    }
}
