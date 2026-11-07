using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using IdentityServerPersistence.Services.SourceTenantGrants;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for managing cross-tenant user role mappings.
/// Each mapping links a user from a parent (source) tenant to roles in the current (child) tenant.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ExternalTenantUserMappingsController(
    IExternalTenantUserMappingStore mappingStore,
    IGroupStore groupStore,
    IRoleChangeGuard roleChangeGuard,
    IRoleChangeRefusals roleChangeRefusals,
    ICrossTenantGrantAuditRecorder grantAudit,
    IMultiTenancyResolverService multiTenancyResolverService,
    ISourceTenantGrantAdmission grantAdmission,
    ILogger<ExternalTenantUserMappingsController> logger) : ControllerBase
{
    /// <summary>User name (or client id) of the caller, for logs and audit events — never a token.</summary>
    private string CallerName()
        => User.Identity?.Name ?? User.FindFirst("preferred_username")?.Value ??
           User.FindFirst("client_id")?.Value ?? User.FindFirst("sub")?.Value ?? "unknown";

    /// <summary>The mapping's group names for an audit event; a read error yields none and never fails the request.</summary>
    private async Task<IReadOnlyList<string>> GroupNamesForAuditAsync(RtExternalTenantUserMapping mapping)
    {
        try
        {
            return await groupStore.GetGroupNamesForExternalUserMappingAsync(mapping.RtId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Group names of mapping {MappingId} could not be read for the audit event (AB#8342)",
                mapping.RtId);
            return [];
        }
    }

    /// <summary>Records a grant event in T and S (AB#8342); never fails the request.</summary>
    private async Task AuditGrantAsync(string eventName, RtExternalTenantUserMapping mapping,
        IReadOnlyList<string>? groupNames = null)
    {
        try
        {
            groupNames ??= await GroupNamesForAuditAsync(mapping);
            await grantAudit.RecordGrantAsync(eventName, multiTenancyResolverService.GetTenantId(), CallerName(),
                mapping, groupNames);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Audit event {EventName} of mapping {MappingId} could not be recorded (AB#8342)",
                eventName, mapping.RtId);
        }
    }

    /// <summary>
    /// Runs the role change guard (AB#7927). Returns the 403/409 problem answer (audited), or <c>null</c> when allowed.
    /// </summary>
    private async Task<ObjectResult?> GuardAsync(RoleGraphChange change, string target)
    {
        var caller = RoleChangeCaller.FromPrincipal(User);
        var decision = await roleChangeGuard.EvaluateAsync(caller, change, HttpContext.RequestAborted);
        return decision.IsAllowed
            ? null
            : await roleChangeRefusals.RefuseAsync(HttpContext, caller, decision, target);
    }

    /// <summary>
    /// Returns all external tenant user mappings.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns all external tenant user mappings.")]
    [ProducesResponseType(typeof(IEnumerable<ExternalTenantUserMappingDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<ExternalTenantUserMappingDto>>> GetAll(
        [FromQuery] int? skip = null,
        [FromQuery] int? take = null,
        [FromQuery] string? sourceTenantId = null)
    {
        IEnumerable<RtExternalTenantUserMapping> mappings;

        if (!string.IsNullOrEmpty(sourceTenantId))
        {
            mappings = await mappingStore.GetBySourceTenantAsync(sourceTenantId);
        }
        else
        {
            mappings = await mappingStore.GetAllAsync(skip, take);
        }

        var dtos = new List<ExternalTenantUserMappingDto>();
        foreach (var mapping in mappings)
        {
            var groupNames = await groupStore.GetGroupNamesForExternalUserMappingAsync(mapping.RtId);
            dtos.Add(MapToDto(mapping, groupNames));
        }

        return Ok(dtos);
    }

    /// <summary>
    /// Returns a specific external tenant user mapping by ID.
    /// </summary>
    [HttpGet("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns an external tenant user mapping by its ID.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> GetById(
        [Required] OctoObjectId rtId)
    {
        var mapping = await mappingStore.GetByIdAsync(rtId);
        if (mapping == null)
        {
            return NotFound();
        }

        var groupNames = await groupStore.GetGroupNamesForExternalUserMappingAsync(mapping.RtId);
        return Ok(MapToDto(mapping, groupNames));
    }

    /// <summary>
    /// Creates a new external tenant user mapping, optionally as a member of groups of this tenant.
    /// </summary>
    /// <remarks>
    /// The source tenant must be a registry ancestor of this tenant or permit it (its allow-list, AB#8345), and the user
    /// must exist in the source tenant (for a non-ancestor also: no shadow user, may sign in). Every refusal answers the
    /// same <c>403 SourceTenantNotPermitted</c>. The stored user name is the one of the source tenant's user record, not
    /// <c>sourceUserName</c> of the request. A <c>groupIds</c> entry that is no group of this tenant answers
    /// <c>400 UnknownGroup</c> and nothing is stored. Contract: <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §2.2 (AB#8343).
    /// </remarks>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Creates a new external tenant user mapping.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest, "application/problem+json")]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden, "application/problem+json")]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> Create(
        [Required][FromBody][Description("The mapping data")] CreateExternalTenantUserMappingDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // AB#8343: registry ancestor or permitted by S, and the user exists in S — one 403 for every refusal.
        var source = await grantAdmission.AdmitAsync(multiTenancyResolverService.GetTenantId(), dto.SourceTenantId,
            dto.SourceUserId, HttpContext?.RequestAborted ?? CancellationToken.None);
        if (source == null)
        {
            return ExternalTenantUserMappingProblems.SourceTenantNotPermitted();
        }

        // A mapping is unique per (source tenant, source user): a second one would lock the user out (AB#6975).
        var duplicate = await mappingStore.FindBySourceUserAsync(source.SourceTenantId, source.SourceUserId);
        if (duplicate != null)
        {
            return ExternalTenantUserMappingProblems.AlreadyExists(duplicate, source.SourceTenantId,
                source.SourceUserId);
        }

        var (groups, unknownGroupIds) = await ResolveGroupsAsync(dto.GroupIds);
        if (unknownGroupIds.Count > 0)
        {
            return ExternalTenantUserMappingProblems.UnknownGroup(unknownGroupIds);
        }

        var refusal = await GuardAsync(new RoleGraphChange.MappingRoles(null, source.SourceTenantId,
                source.SourceUserName, dto.RoleIds ?? [], groups.Select(g => g.RtId.ToString()).ToList()),
            $"mapping {source.SourceTenantId}/{source.SourceUserName}");
        if (refusal != null)
        {
            return refusal;
        }

        if (!string.Equals(dto.SourceUserName, source.SourceUserName, StringComparison.Ordinal))
        {
            logger.LogInformation(
                "Mapping create: the requested user name differs from the user record of source tenant {SourceTenantId}; the record's name is stored (AB#8343)",
                source.SourceTenantId);
        }

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = source.SourceTenantId,
            SourceUserId = source.SourceUserId,
            SourceUserName = source.SourceUserName,
            MappedRoleIds = dto.RoleIds != null
                ? new AttributeStringValueList(dto.RoleIds)
                : null
        };

        var groupNames = groups.Select(g => g.GroupName).ToList();
        if (groups.Count > 0)
        {
            await mappingStore.InsertWithGroupsAsync(mapping, groups);
        }
        else
        {
            await mappingStore.StoreAsync(mapping);
        }

        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantCreated, mapping, groupNames);

        // NB: use Created(location, value) rather than CreatedAtAction(nameof(GetById), …). The
        // GetById action takes an OctoObjectId route value, for which no route template matches when
        // MVC formats the 201 Location header — CreatedAtAction then threw
        // "No route matches the supplied values" AFTER the entity was already stored, surfacing as a
        // 500 to octo-cli (the mapping was created regardless). A relative self-link avoids the
        // link-generation step entirely.
        return Created($"{Request.Path}/{mapping.RtId}", MapToDto(mapping, groupNames));
    }

    /// <summary>
    /// The groups of this tenant named by <paramref name="groupIds"/> (duplicates once), and the ids that are no group
    /// of this tenant (malformed ids included). <c>null</c> or empty: no groups.
    /// </summary>
    private async Task<(List<RtGroup> Groups, List<string> UnknownGroupIds)> ResolveGroupsAsync(
        IReadOnlyCollection<string>? groupIds)
    {
        var groups = new List<RtGroup>();
        var unknown = new List<string>();
        foreach (var groupId in (groupIds ?? []).Distinct(StringComparer.Ordinal))
        {
            var group = groupId != null && OctoObjectId.TryParse(groupId, out var rtId)
                ? await groupStore.FindByIdAsync(rtId)
                : null;
            if (group == null)
            {
                unknown.Add(groupId ?? string.Empty);
            }
            else if (groups.All(g => g.RtId != group.RtId))
            {
                groups.Add(group);
            }
        }

        return (groups, unknown);
    }

    /// <summary>
    /// Finds exactly one user of a source tenant by exact user name or exact e-mail, so an administrator of this (target)
    /// tenant can grant that user access without seeing the source tenant's user directory (AB#8341).
    /// </summary>
    /// <remarks>
    /// Every negative case answers the same <c>404</c> (<c>SourceUserNotFound</c>): source tenant absent, source tenant
    /// neither a registry ancestor nor permitting this tenant, empty identifier, no or more than one matching user, a
    /// shadow (<c>xt_</c>) user, a locked-out or sign-in-blocked user. Limited per caller and tenant
    /// (<c>Identity:SourceUserLookupRateLimit</c>, default 20 per 10 minutes) → <c>429</c> with <c>Retry-After</c> and
    /// <c>retryAfterSeconds</c>. Contract: <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c>.
    /// </remarks>
    [HttpPost("sourceUserLookup")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Finds one user of a source tenant by exact user name or e-mail.")]
    [ProducesResponseType(typeof(SourceUserLookupResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound, "application/problem+json")]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests, "application/problem+json")]
    public async Task<ActionResult<SourceUserLookupResultDto>> LookupSourceUser(
        // ValidateNever: an empty or missing sourceTenantId / identifier is a negative case (uniform 404), not a 400 of
        // the implicit [Required] on the DTO's non-nullable strings.
        [FromBody][ValidateNever][Description("Source tenant id and exact user name or e-mail")]
        SourceUserLookupRequestDto request,
        [FromServices] ISourceUserLookupService lookupService,
        [FromServices] ISourceUserLookupRateLimiter rateLimiter)
    {
        var targetTenantId = multiTenancyResolverService.GetTenantId();
        var callerKey = User.FindFirst("sub")?.Value ?? $"client:{User.FindFirst("client_id")?.Value}";
        if (rateLimiter.TryAcquire(callerKey, targetTenantId) is { } retryAfterSeconds)
        {
            return SourceUserLookupProblems.RateLimited(Response, retryAfterSeconds);
        }

        var match = await lookupService.LookupAsync(targetTenantId, request.SourceTenantId, request.Identifier,
            CallerName(), HttpContext.RequestAborted);
        if (match == null)
        {
            return SourceUserLookupProblems.NotFound();
        }

        return Ok(new SourceUserLookupResultDto
        {
            SourceTenantId = match.SourceTenantId,
            UserId = match.UserId,
            UserName = match.UserName,
            DisplayName = match.DisplayName
        });
    }

    /// <summary>
    /// Updates an existing external tenant user mapping (changes roles).
    /// </summary>
    [HttpPut("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Updates an existing external tenant user mapping.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> Update(
        [Required] OctoObjectId rtId,
        [Required][FromBody][Description("The updated mapping data")] UpdateExternalTenantUserMappingDto dto)
    {
        var existing = await mappingStore.GetByIdAsync(rtId);
        if (existing == null)
        {
            return NotFound();
        }

        var refusal = await GuardAsync(new RoleGraphChange.MappingRoles(rtId.ToString(), null, null, dto.RoleIds ?? []),
            $"mapping {rtId}");
        if (refusal != null)
        {
            return refusal;
        }

        existing.MappedRoleIds = dto.RoleIds != null
            ? new AttributeStringValueList(dto.RoleIds)
            : null;

        await mappingStore.StoreAsync(existing);
        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantChanged, existing);

        return Ok(MapToDto(existing));
    }

    /// <summary>
    /// Deletes an external tenant user mapping.
    /// </summary>
    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Deletes an external tenant user mapping.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete([Required] OctoObjectId rtId)
    {
        var existing = await mappingStore.GetByIdAsync(rtId);
        if (existing == null)
        {
            return NotFound();
        }

        var refusal = await GuardAsync(new RoleGraphChange.MappingDeleted(rtId.ToString()), $"mapping {rtId}");
        if (refusal != null)
        {
            return refusal;
        }

        // Group names before the removal: the mapping's GroupMember edges go with it.
        var groupNames = await GroupNamesForAuditAsync(existing);
        await mappingStore.RemoveAsync(rtId);
        await AuditGrantAsync(CrossTenantGrantAuditEvents.GrantRemoved, existing, groupNames);
        return Ok();
    }

    // Create/Update responses: the per-tenant mapping is not yet (or not) a group member at that point,
    // so group names are resolved only on the read paths (GetAll/GetById).
    private static ExternalTenantUserMappingDto MapToDto(RtExternalTenantUserMapping mapping) =>
        MapToDto(mapping, []);

    private static ExternalTenantUserMappingDto MapToDto(
        RtExternalTenantUserMapping mapping, IReadOnlyList<string> groupNames) =>
        new()
        {
            Id = mapping.RtId,
            SourceTenantId = mapping.SourceTenantId,
            SourceUserId = mapping.SourceUserId,
            SourceUserName = mapping.SourceUserName,
            RoleIds = mapping.MappedRoleIds?.ToList() ?? [],
            GroupNames = groupNames.ToList()
        };
}

