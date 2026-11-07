using System.ComponentModel;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.SourceTenantGrants;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// The allow-list of this tenant as a <b>source</b> of sibling-tenant grants (AB#8345, decision 2026-11-06 option A,
/// contract <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §6): the target tenants whose administrators may look up this
/// tenant's users by exact user name or e-mail and grant them access. Empty = nobody (the default of every tenant).
/// </summary>
/// <remarks>
/// Only this tenant's administrators read or change it (<see cref="IdentityServiceConstants.IdentityCrossTenantGrantPermissionsPolicy" />:
/// <c>UserManagement</c> and <c>TenantManagement</c>, token issued for this tenant). No route of any tenant reveals which
/// tenants permit a target tenant.
/// </remarks>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class CrossTenantGrantPermissionsController(
    ICrossTenantGrantPermissionStore permissionStore,
    IMultiTenancyResolverService multiTenancyResolverService,
    TimeProvider timeProvider,
    ILogger<CrossTenantGrantPermissionsController> logger) : ControllerBase
{
    /// <summary>
    /// Returns the target tenants this tenant permits to look up and grant access to its users.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityCrossTenantGrantPermissionsPolicy)]
    [EndpointSummary("Returns the target tenants this tenant permits to look up and grant access to its users.")]
    [ProducesResponseType(typeof(CrossTenantGrantPermissionsDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<CrossTenantGrantPermissionsDto>> Get()
    {
        var permissions = await ReadEffectiveAsync(multiTenancyResolverService.GetTenantRepository());
        return Ok(new CrossTenantGrantPermissionsDto { TargetTenantIds = permissions.TargetTenantIds });
    }

    /// <summary>
    /// Replaces the list of target tenants this tenant permits. <c>[]</c> permits nobody; a removed tenant's lookups and
    /// new grants stop with its next request.
    /// </summary>
    /// <remarks>
    /// Entries are trimmed, lower-cased and de-duplicated. Each must be a valid tenant id (at most 64 ASCII letters,
    /// digits, <c>-</c> or <c>_</c>), at most 200 entries, not this tenant itself. The entries are not checked for
    /// existence, so the route reveals nothing about which tenants exist.
    /// </remarks>
    [HttpPut]
    [Authorize(IdentityServiceConstants.IdentityCrossTenantGrantPermissionsPolicy)]
    [EndpointSummary("Replaces the target tenants this tenant permits to look up and grant access to its users.")]
    [ProducesResponseType(typeof(CrossTenantGrantPermissionsDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<CrossTenantGrantPermissionsDto>> Put(
        // ValidateNever: the list is validated below with one combined, readable answer.
        [FromBody][ValidateNever][Description("The complete list of permitted target tenant ids")]
        CrossTenantGrantPermissionsDto dto)
    {
        var tenantId = multiTenancyResolverService.GetTenantId();
        var errors = CrossTenantGrantPermissionList.Validate(tenantId, dto.TargetTenantIds);
        if (errors.Count > 0)
        {
            foreach (var error in errors)
            {
                ModelState.AddModelError(nameof(CrossTenantGrantPermissionsDto.TargetTenantIds), error);
            }

            return ValidationProblem(ModelState);
        }

        var repository = multiTenancyResolverService.GetTenantRepository();
        var before = await ReadEffectiveAsync(repository);
        var callerName = User.Identity?.Name ?? User.FindFirst("preferred_username")?.Value ??
            User.FindFirst("client_id")?.Value ?? User.FindFirst("sub")?.Value ?? "unknown";
        var after = new CrossTenantGrantPermissions
        {
            TargetTenantIds = CrossTenantGrantPermissionList.Normalize(dto.TargetTenantIds!),
            ChangedAtUtc = timeProvider.GetUtcNow().UtcDateTime,
            ChangedBy = callerName
        };
        await permissionStore.SetAsync(repository, after);

        var added = after.TargetTenantIds.Except(before.TargetTenantIds, StringComparer.Ordinal).ToList();
        var removed = before.TargetTenantIds.Except(after.TargetTenantIds, StringComparer.Ordinal).ToList();
        logger.LogInformation(
            "Cross-tenant grant permissions of tenant {TenantId} replaced by {CallerName}: added [{Added}], removed [{Removed}], now [{TargetTenantIds}] (AB#8345)",
            tenantId, callerName, string.Join(",", added), string.Join(",", removed),
            string.Join(",", after.TargetTenantIds));

        return Ok(new CrossTenantGrantPermissionsDto { TargetTenantIds = after.TargetTenantIds });
    }

    /// <summary>
    /// The list as the grant policy applies it. A stored value that is no valid list (written by hand) permits nobody
    /// (the policy fails closed), so it reads as empty here — and a <c>PUT</c> can repair it.
    /// </summary>
    private async Task<CrossTenantGrantPermissions> ReadEffectiveAsync(
        Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories.ITenantRepository repository)
    {
        try
        {
            return await permissionStore.GetAsync(repository);
        }
        catch (System.Text.Json.JsonException ex)
        {
            logger.LogWarning(ex,
                "Cross-tenant grant permissions of tenant {TenantId} are unreadable; they permit nobody until replaced (AB#8345)",
                multiTenancyResolverService.GetTenantId());
            return new CrossTenantGrantPermissions();
        }
    }
}

/// <summary>
/// Body of <c>GET/PUT {tenant}/v1/CrossTenantGrantPermissions</c> (AB#8345): the target tenants this (source) tenant
/// permits to look up and grant access to its users.
/// </summary>
public sealed class CrossTenantGrantPermissionsDto
{
    /// <summary>Target tenant ids; empty = nobody. Required on <c>PUT</c> (send <c>[]</c> to clear).</summary>
    public List<string>? TargetTenantIds { get; set; }
}
