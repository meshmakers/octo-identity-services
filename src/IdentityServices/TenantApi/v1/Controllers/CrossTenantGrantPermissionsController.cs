using System.ComponentModel;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.SourceTenantGrants;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using IdentityServerPersistence.Configuration.Options;

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
    IIdentityAuditService auditService,
    TimeProvider timeProvider,
    IOptions<OctoIdentityServicesOptions> identityOptions,
    ILogger<CrossTenantGrantPermissionsController> logger) : ControllerBase
{
    /// <summary>Problem <c>code</c> of the <c>412</c>: the list changed since the caller read it (AB#8432).</summary>
    public const string ListChangedCode = "CrossTenantGrantPermissionsChanged";

    /// <summary>Problem <c>code</c> of the <c>428</c>: <c>If-Match</c> is required and missing (AB#8432).</summary>
    public const string IfMatchRequiredCode = "IfMatchRequired";

    /// <summary>
    /// Returns the target tenants this tenant permits to look up and grant access to its users, with the list's entity
    /// tag in the <c>ETag</c> header (AB#8432) for the <c>If-Match</c> of the next <c>PUT</c>.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityCrossTenantGrantPermissionsPolicy)]
    [EndpointSummary("Returns the target tenants this tenant permits to look up and grant access to its users.")]
    [ProducesResponseType(typeof(CrossTenantGrantPermissionsDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<CrossTenantGrantPermissionsDto>> Get()
    {
        var permissions = await ReadEffectiveAsync(multiTenancyResolverService.GetTenantRepository());
        return Answer(permissions.TargetTenantIds);
    }

    /// <summary>
    /// Replaces the list of target tenants this tenant permits. <c>[]</c> permits nobody; a removed tenant's lookups and
    /// new grants stop with its next request.
    /// </summary>
    /// <remarks>
    /// Entries are trimmed, lower-cased and de-duplicated. Each must be a valid tenant id (at most 64 ASCII letters,
    /// digits, <c>-</c> or <c>_</c>), at most 200 entries, not this tenant itself. The entries are not checked for
    /// existence, so the route reveals nothing about which tenants exist.
    /// <para>
    /// Concurrency (AB#8432): send the <c>ETag</c> of the <c>GET</c> (or of the last <c>PUT</c>) as <c>If-Match</c>.
    /// When the list changed in between, the answer is <c>412</c> (problem code <c>CrossTenantGrantPermissionsChanged</c>,
    /// current tag in <c>ETag</c>) and nothing is written. Without <c>If-Match</c> the answer is <c>428</c> (code
    /// <c>IfMatchRequired</c>) when <c>Identity:CrossTenantGrantPermissions:RequireIfMatch</c> is on; while it is off
    /// (default during the client rollout) the list is replaced unconditionally. A <c>PUT</c> that leaves the list as it
    /// is writes nothing and records no event.
    /// </para>
    /// </remarks>
    [HttpPut]
    [Authorize(IdentityServiceConstants.IdentityCrossTenantGrantPermissionsPolicy)]
    [EndpointSummary("Replaces the target tenants this tenant permits to look up and grant access to its users.")]
    [ProducesResponseType(typeof(CrossTenantGrantPermissionsDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status412PreconditionFailed)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status428PreconditionRequired)]
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

        var ifMatch = ParseIfMatch();
        if (ifMatch == null && identityOptions.Value.CrossTenantGrantPermissions.RequireIfMatch)
        {
            return PreconditionProblem(StatusCodes.Status428PreconditionRequired, IfMatchRequiredCode, "If-Match required",
                "Send the ETag of the list as read before in the If-Match header.");
        }

        var callerName = User.Identity?.Name ?? User.FindFirst("preferred_username")?.Value ??
            User.FindFirst("client_id")?.Value ?? User.FindFirst("sub")?.Value ?? "unknown";
        var result = await permissionStore.ReplaceAsync(multiTenancyResolverService.GetTenantRepository(),
            CrossTenantGrantPermissionList.Normalize(dto.TargetTenantIds!), ifMatch,
            callerName, timeProvider.GetUtcNow().UtcDateTime);

        switch (result.Outcome)
        {
            case CrossTenantGrantPermissionsReplaceOutcome.PreconditionFailed:
                logger.LogInformation(
                    "Cross-tenant grant permissions of tenant {TenantId} not replaced by {CallerName}: the list changed since it was read (AB#8432)",
                    tenantId, callerName);
                Response.Headers.ETag = result.ETag;
                return PreconditionProblem(StatusCodes.Status412PreconditionFailed, ListChangedCode, "List changed",
                    "The list was changed by someone else since it was read. Read it again and apply the change to the current list.");
            case CrossTenantGrantPermissionsReplaceOutcome.Unchanged:
                // AB#8432 (Ariadne review of #275): nothing written, not even ChangedBy/ChangedAtUtc, and no event.
                return Answer(result.Current);
        }

        var added = result.Current.Except(result.Before, StringComparer.Ordinal).ToList();
        var removed = result.Before.Except(result.Current, StringComparer.Ordinal).ToList();
        logger.LogInformation(
            "Cross-tenant grant permissions of tenant {TenantId} replaced by {CallerName}: added [{Added}], removed [{Removed}], now [{TargetTenantIds}] (AB#8345)",
            tenantId, callerName, string.Join(",", added), string.Join(",", removed),
            string.Join(",", result.Current));

        // AB#8342 audit API: a change is written into this (source) tenant's event log only. Only a PUT that changed
        // the list gets here (an unreadable row that a PUT repairs counts as changed). Never throws into the request.
        if (added.Count > 0 || removed.Count > 0)
        {
            await auditService.StoreInfoAsync(tenantId, CrossTenantGrantAuditEvents.GrantPermissionsChanged,
                $"Cross-tenant grant permissions of tenant '{tenantId}' changed by '{callerName}'",
                new Dictionary<string, string>
                {
                    ["actorTenantId"] = tenantId,
                    ["actorName"] = callerName,
                    ["sourceTenantId"] = tenantId,
                    ["permittedTargetTenantIds"] = string.Join(",", result.Current),
                    ["addedTargetTenantIds"] = string.Join(",", added),
                    ["removedTargetTenantIds"] = string.Join(",", removed)
                });
        }

        return Answer(result.Current);
    }

    /// <summary>The list with its entity tag in the <c>ETag</c> header (AB#8432).</summary>
    private OkObjectResult Answer(IReadOnlyList<string> targetTenantIds)
    {
        Response.Headers.ETag = CrossTenantGrantPermissionList.ETagOf(targetTenantIds);
        return Ok(new CrossTenantGrantPermissionsDto { TargetTenantIds = targetTenantIds.ToList() });
    }

    /// <summary>
    /// The <c>If-Match</c> precondition of the request (RFC 9110 §13.1.1), or <c>null</c> when the header is absent.
    /// Strong comparison: a weak tag (<c>W/"…"</c>) or an unparsable header never matches; <c>*</c> matches any list
    /// (the list always exists, it may be empty).
    /// </summary>
    private Func<string, bool>? ParseIfMatch()
    {
        var values = Request.Headers.IfMatch;
        if (values.Count == 0)
        {
            return null;
        }

        if (!EntityTagHeaderValue.TryParseList(values, out var tags) || tags.Count == 0)
        {
            return _ => false;
        }

        if (tags.Any(t => t.Equals(EntityTagHeaderValue.Any)))
        {
            return _ => true;
        }

        return current => tags.Any(t => !t.IsWeak && string.Equals(t.Tag.Value, current, StringComparison.Ordinal));
    }

    private static ObjectResult PreconditionProblem(int status, string code, string title, string detail)
        => new(new ProblemDetails { Status = status, Title = title, Detail = detail, Extensions = { ["code"] = code } })
        {
            StatusCode = status,
            ContentTypes = { "application/problem+json" }
        };

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
