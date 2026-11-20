using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
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
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Meshmakers.Octo.Services.RestDeprecation;

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
    IRoleChangeRefusals roleChangeRefusals,
    IMultiTenancyResolverService multiTenancyResolverService,
    IIdentityMethodFacade methodFacade) : ControllerBase
{
    /// <summary>User name (or client id) of the caller, for logs and audit events — never a token.</summary>
    private string CallerName()
        => User.Identity?.Name ?? User.FindFirst("preferred_username")?.Value ??
           User.FindFirst("client_id")?.Value ?? User.FindFirst("sub")?.Value ?? "unknown";

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
    /// Creates a new external tenant user mapping, optionally as a member of groups of this tenant. Facade of the CK
    /// method <c>ExternalTenantUserMapping.CreateMapping-1</c>.
    /// </summary>
    /// <remarks>
    /// The source tenant must be a registry ancestor of this tenant or permit it (its allow-list), and the user
    /// must exist in the source tenant (for a non-ancestor also: no shadow user, may sign in). Every refusal answers the
    /// same <c>403 SourceTenantNotPermitted</c>. The stored user name is the one of the source tenant's user record, not
    /// <c>sourceUserName</c> of the request. A <c>groupIds</c> entry that is no group of this tenant answers
    /// <c>400 UnknownGroup</c> and nothing is stored. Contract: <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §2.2.
    /// </remarks>
    [HttpPost]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.AdminProvisioningMethodsLink)]
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

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId, null,
            new ExternalTenantUserMappingCreateMappingParameters
            {
                SourceTenantId = dto.SourceTenantId,
                SourceUserId = dto.SourceUserId,
                SourceUserName = dto.SourceUserName,
                RoleIds = dto.RoleIds?.ToList(),
                GroupIds = dto.GroupIds?.ToList()
            }, User, HttpContext?.RequestAborted ?? CancellationToken.None);

        // A refusal of the role change guard keeps its REST answer (403/409 problem, WARN log, audit record).
        if (RoleChangeProblems.RefusalOf(response) is { } decision)
        {
            return await roleChangeRefusals.RefuseAsync(HttpContext!, RoleChangeCaller.FromPrincipal(User), decision,
                $"mapping {dto.SourceTenantId}/{dto.SourceUserName}");
        }

        var result = response.ToActionResult(new CkMethodFacadeOptions()
            .MapSuccess(success =>
            {
                var record = ClientMirrorController.Deserialize<RtAdminProvisioningResultRecord>(success.ResultJson);
                var created = new ExternalTenantUserMappingDto
                {
                    Id = OctoObjectId.Parse(record.MappingRtId),
                    SourceTenantId = record.SourceTenantId,
                    SourceUserId = record.SourceUserId,
                    SourceUserName = record.SourceUserName,
                    RoleIds = record.RoleIds?.ToList() ?? [],
                    GroupNames = record.GroupNames?.ToList() ?? []
                };

                // A relative self-link (not CreatedAtAction): the GetById route value is an OctoObjectId, for which no
                // route template matches when MVC formats the Location header.
                return Created($"{Request.Path}/{record.MappingRtId}", created);
            })
            .MapError(AdminProvisioningMethodErrors.SourceTenantNotPermitted,
                _ => ExternalTenantUserMappingProblems.SourceTenantNotPermitted())
            .MapError(AdminProvisioningMethodErrors.MappingAlreadyExists, error =>
                ExternalTenantUserMappingProblems.AlreadyExists(
                    error.Parameters.GetValueOrDefault(AdminProvisioningMethodErrors.ExistingMappingIdParameter) ??
                    string.Empty, dto.SourceTenantId, dto.SourceUserId))
            .MapError(AdminProvisioningMethodErrors.UnknownGroup, error =>
                ExternalTenantUserMappingProblems.UnknownGroup(
                    (error.Parameters.GetValueOrDefault(AdminProvisioningMethodErrors.UnknownGroupIdsParameter) ??
                     string.Empty).Split(',').ToList())));
        return result is ActionResult actionResult ? actionResult : new ObjectResult(result);
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
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.CrudWave2MethodsLink)]
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

        // The facade of ExternalTenantUserMapping.UpdateMapping-1 (System.Identity 3.8.0): the role change guard
        // and the grant audit run in the method; a refusal keeps its audited 403/409 answer.
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            SystemIdentityCkIds.ExternalTenantUserMappingUpdateMappingMethodId, rtId.ToString(),
            new ExternalTenantUserMappingUpdateMappingParameters { RoleIds = dto.RoleIds?.ToList() }, User,
            HttpContext.RequestAborted);
        if (!response.Success)
        {
            return (ActionResult)await FacadeFailureAsync(response, $"mapping {rtId}");
        }

        var updated = await mappingStore.GetByIdAsync(rtId);
        return updated == null ? NotFound() : Ok(MapToDto(updated));
    }

    /// <summary>
    /// Deletes an external tenant user mapping.
    /// </summary>
    [HttpDelete("{rtId}")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.CrudWave2MethodsLink)]
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

        // The facade of ExternalTenantUserMapping.DeleteMapping-1 (System.Identity 3.8.0); guard and grant audit
        // run in the method.
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            SystemIdentityCkIds.ExternalTenantUserMappingDeleteMappingMethodId, rtId.ToString(),
            new ExternalTenantUserMappingDeleteMappingParameters(), User, HttpContext.RequestAborted);
        return response.Success ? Ok() : await FacadeFailureAsync(response, $"mapping {rtId}");
    }

    /// <summary>
    ///     The REST answer of a refused mapping method: a role change guard refusal keeps the audited 403/409 problem of the
    ///     REST endpoint; everything else maps as the facade defaults (404 for an unknown or invisible mapping).
    /// </summary>
    private async Task<IActionResult> FacadeFailureAsync(CkMethodResponse response, string target)
    {
        if (RoleChangeProblems.RefusalOf(response) is { } decision)
        {
            return await roleChangeRefusals.RefuseAsync(HttpContext, RoleChangeCaller.FromPrincipal(User), decision,
                target);
        }

        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => NotFound()));
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

