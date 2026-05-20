using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for managing cross-tenant user role mappings.
/// Each mapping links a user from a parent (source) tenant to roles in the current (child) tenant.
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ExternalTenantUserMappingsController(
    IExternalTenantUserMappingStore mappingStore) : ControllerBase
{
    /// <summary>
    /// Returns all external tenant user mappings.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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

        return Ok(mappings.Select(MapToDto));
    }

    /// <summary>
    /// Returns a specific external tenant user mapping by ID.
    /// </summary>
    [HttpGet("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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

        return Ok(MapToDto(mapping));
    }

    /// <summary>
    /// Creates a new external tenant user mapping.
    /// </summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new external tenant user mapping.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> Create(
        [Required][FromBody][Description("The mapping data")] CreateExternalTenantUserMappingDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = dto.SourceTenantId,
            SourceUserId = dto.SourceUserId,
            SourceUserName = dto.SourceUserName,
            MappedRoleIds = dto.RoleIds != null
                ? new AttributeStringValueList(dto.RoleIds)
                : null
        };

        await mappingStore.StoreAsync(mapping);

        return CreatedAtAction(
            nameof(GetById),
            new { rtId = mapping.RtId },
            MapToDto(mapping));
    }

    /// <summary>
    /// Updates an existing external tenant user mapping (changes roles).
    /// </summary>
    [HttpPut("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
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

        existing.MappedRoleIds = dto.RoleIds != null
            ? new AttributeStringValueList(dto.RoleIds)
            : null;

        await mappingStore.StoreAsync(existing);

        return Ok(MapToDto(existing));
    }

    /// <summary>
    /// Deletes an external tenant user mapping.
    /// </summary>
    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
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

        await mappingStore.RemoveAsync(rtId);
        return Ok();
    }

    private static ExternalTenantUserMappingDto MapToDto(RtExternalTenantUserMapping mapping) =>
        new()
        {
            Id = mapping.RtId,
            SourceTenantId = mapping.SourceTenantId,
            SourceUserId = mapping.SourceUserId,
            SourceUserName = mapping.SourceUserName,
            RoleIds = mapping.MappedRoleIds?.ToList() ?? []
        };
}

public record ExternalTenantUserMappingDto
{
    public OctoObjectId? Id { get; init; }
    public string SourceTenantId { get; init; } = string.Empty;
    public string SourceUserId { get; init; } = string.Empty;
    public string SourceUserName { get; init; } = string.Empty;
    public List<string> RoleIds { get; init; } = [];
    public List<string> GroupNames { get; init; } = [];
}

public record CreateExternalTenantUserMappingDto
{
    [Required]
    public string SourceTenantId { get; init; } = string.Empty;

    [Required]
    public string SourceUserId { get; init; } = string.Empty;

    [Required]
    public string SourceUserName { get; init; } = string.Empty;

    public List<string>? RoleIds { get; init; }
}

public record UpdateExternalTenantUserMappingDto
{
    public List<string>? RoleIds { get; init; }
}
