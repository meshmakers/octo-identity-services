using System.Security.Claims;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Infrastructure.Routing;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
///     Tenant topology for apps (AB#7044): which of the signed-in user's allowed tenants lie below an app's root
///     tenant and whether each has children — answered by identity, so an app needs no cross-tenant call that
///     the user-token tenant gate (AB#6728) would reject.
/// </summary>
/// <remarks>
///     <para>
///         The route has <b>no</b> <c>{tenantId}</c> segment on purpose: the tenant gate
///         (<c>TenantAuthorizationMiddleware</c>) skips routes without a tenant segment, so this needs no
///         exemption marker and no change in octo-common-services. A wiring test fails when someone adds a
///         tenant segment.
///     </para>
///     <para>
///         Only user tokens: a client-credentials token (no <c>sub</c>) is answered 403. No role is required —
///         the entitlement is the token's <c>allowed_tenants</c> claim, which here only limits which topology
///         facts (tenantId, depth, hasChildren) are revealed. Logs carry counts and the scope id only.
///     </para>
/// </remarks>
[ApiController]
[Route("api/tenant-topology")]
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme,
    Policy = IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
public class TenantTopologyApiController(
    ITenantTopologyService topologyService,
    ITenantTopologyRateLimiter rateLimiter,
    ILogger<TenantTopologyApiController> logger) : ControllerBase
{
    private const string AllowedTenantsClaim = "allowed_tenants";

    /// <summary>
    ///     The tenants below <paramref name="scope" /> that the caller is allowed to use, each with its depth below
    ///     the scope (1 = direct child) and whether it has children itself.
    /// </summary>
    /// <param name="scope">The app's root tenant.</param>
    [HttpGet]
    [EndpointSummary("Tenants below a scope tenant that the signed-in user may use")]
    [EndpointDescription(
        "Returns (allowed_tenants of the user token) intersected with (strict descendants of the scope), each with depth and hasChildren. " +
        "An unknown scope answers like a scope without entitled descendants (200, empty). User tokens only.")]
    [ProducesResponseType(typeof(TenantTopologyDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Get([FromQuery] string? scope)
    {
        // A client-credentials token has no user and therefore no allowed tenants.
        var subject = User.FindFirst("sub")?.Value ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(subject))
        {
            return Forbid(AuthenticationConstants.BearerAuthenticationScheme);
        }

        if (string.IsNullOrWhiteSpace(scope))
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "The query parameter 'scope' is required.");
        }

        if (!rateLimiter.TryAcquire(subject))
        {
            Response.Headers.RetryAfter = "60";
            return StatusCode(StatusCodes.Status429TooManyRequests);
        }

        var scopeTenantId = scope.Trim();
        var allowedTenants = User.FindAll(AllowedTenantsClaim).Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v)).ToList();

        // A value that cannot name a tenant is an unknown scope, answered like any other unknown scope.
        var result = TenantIdRouteConstraint.IsWellFormed(scopeTenantId)
            ? await GetTopologyOrNullAsync(scopeTenantId, allowedTenants)
            : new TenantTopologyResult(scopeTenantId, false, []);
        if (result == null)
        {
            return Problem(statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "The tenant hierarchy could not be read. Try again later.");
        }

        logger.LogDebug("Tenant topology for scope '{Scope}': {Count} of {Allowed} allowed tenants listed",
            scopeTenantId, result.Tenants.Count, allowedTenants.Count);

        return Ok(new TenantTopologyDto
        {
            Scope = result.Scope,
            ScopeHasChildren = result.ScopeHasChildren,
            Tenants = result.Tenants
                .Select(t => new TenantTopologyEntryDto
                {
                    TenantId = t.TenantId,
                    Depth = t.Depth,
                    HasChildren = t.HasChildren
                })
                .ToList()
        });
    }

    private async Task<TenantTopologyResult?> GetTopologyOrNullAsync(string scope, IReadOnlyCollection<string> allowed)
    {
        try
        {
            return await topologyService.GetTopologyAsync(scope, allowed);
        }
        catch (TenantHierarchyUnreadableException ex)
        {
            // Fail closed: an app must not decide on a partial list.
            logger.LogWarning(ex, "Tenant topology for scope '{Scope}' is unavailable", scope);
            return null;
        }
    }
}

/// <summary>Response of <c>GET /api/tenant-topology</c> — exactly these fields, nothing else.</summary>
public record TenantTopologyDto
{
    public string Scope { get; init; } = string.Empty;
    public bool ScopeHasChildren { get; init; }
    public List<TenantTopologyEntryDto> Tenants { get; init; } = [];
}

/// <summary>One allowed tenant below the scope.</summary>
public record TenantTopologyEntryDto
{
    public string TenantId { get; init; } = string.Empty;

    /// <summary>1 = direct child of the scope.</summary>
    public int Depth { get; init; }

    /// <summary>The tenant itself has at least one child (the children are not listed).</summary>
    public bool HasChildren { get; init; }
}
