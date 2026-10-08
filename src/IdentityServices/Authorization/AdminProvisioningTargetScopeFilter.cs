using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization;

/// <summary>
///     Restricts cross-tenant admin provisioning to target tenants the caller administers (AB#5859).
/// </summary>
/// <remarks>
///     <para>
///         <c>AdminProvisioningController</c> reaches the target tenant through the system context, so the
///         route tenant says nothing about the target: before AB#5859 any caller holding a token for its own
///         tenant could read and write the identity of <b>any</b> tenant — including provisioning itself into
///         the target's <c>TenantOwners</c> group and registering its tenant as the target's login parent.
///     </para>
///     <para>
///         The target must be the caller's own tenant (<c>tenant_id</c> of the token) or a direct or
///         indirect child of it in the tenant registry. A caller of the system tenant may address every
///         tenant. The registry walk is the one the email-first discovery scope uses
///         (<see cref="ITenantDiscoveryService.GetScopeDescendantsAsync" />).
///     </para>
///     <para>
///         Follows <see cref="IdentityApiAuthorizationOptions.RoleEnforcement" />: <c>Warn</c> logs and
///         lets the call through, <c>Enforce</c> answers <c>403</c>.
///     </para>
/// </remarks>
internal sealed class AdminProvisioningTargetScopeFilter(
    ITenantDiscoveryService tenantDiscoveryService,
    IOptions<OctoSystemConfiguration> systemConfiguration,
    IOptionsMonitor<IdentityApiAuthorizationOptions> options,
    ILogger<AdminProvisioningTargetScopeFilter> logger) : IAsyncActionFilter
{
    internal const string TenantIdClaim = "tenant_id";

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var targetTenantId = context.RouteData.Values["targetTenantId"] as string;
        var callerTenantId = context.HttpContext.User.FindFirst(TenantIdClaim)?.Value;

        if (await IsInCallerScopeAsync(callerTenantId, targetTenantId))
        {
            await next();
            return;
        }

        if (options.CurrentValue.RoleEnforcement == IdentityApiRoleEnforcementMode.Warn)
        {
            logger.LogWarning(
                "Admin provisioning outside the caller's tenant subtree allowed by RoleEnforcement=Warn: caller tenant {CallerTenantId}, target tenant {TargetTenantId}, {Method} {Path}. " +
                "This would be denied with RoleEnforcement=Enforce (AB#5859)",
                callerTenantId, targetTenantId, context.HttpContext.Request.Method,
                context.HttpContext.Request.Path.Value);
            await next();
            return;
        }

        logger.LogWarning(
            "Admin provisioning denied, target outside the caller's tenant subtree: caller tenant {CallerTenantId}, target tenant {TargetTenantId}, {Method} {Path} (AB#5859)",
            callerTenantId, targetTenantId, context.HttpContext.Request.Method,
            context.HttpContext.Request.Path.Value);
        context.Result = new ForbidResult();
    }

    private async Task<bool> IsInCallerScopeAsync(string? callerTenantId, string? targetTenantId)
    {
        if (string.IsNullOrWhiteSpace(callerTenantId) || string.IsNullOrWhiteSpace(targetTenantId))
        {
            return false;
        }

        var caller = callerTenantId.Trim();
        var target = targetTenantId.Trim();

        if (string.Equals(caller, systemConfiguration.Value.SystemTenantId.Trim(),
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(caller, target, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var descendants = await tenantDiscoveryService.GetScopeDescendantsAsync(caller);
        return descendants != null &&
               descendants.Any(d => string.Equals(d, target, StringComparison.OrdinalIgnoreCase));
    }
}
