using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for pre-provisioning cross-tenant user mappings in a target tenant.
/// Routed via the system tenant so that the calling user does not need allowed_tenants for the target tenant.
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]/{targetTenantId}")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class AdminProvisioningController(
    ISystemContext systemContext,
    IDynamicAuthSchemeService dynamicAuthSchemeService,
    ILogger<AdminProvisioningController> logger) : ControllerBase
{
    /// <summary>
    /// Returns all external tenant user mappings in the target tenant.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Returns all external tenant user mappings in the target tenant.")]
    [ProducesResponseType(typeof(IEnumerable<ExternalTenantUserMappingDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IEnumerable<ExternalTenantUserMappingDto>>> GetAll(
        [Required] string targetTenantId)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
        }

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, RtEntityQueryOptions.Create());

        // Build a lookup of mapping RtId → group names via inbound GroupMember associations
        var groupNamesByMappingId = new Dictionary<string, List<string>>();
        foreach (var mapping in result.Items)
        {
            var associations = await tenantRepository.GetRtAssociationsAsync(
                session,
                mapping.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(
                    GraphDirections.Inbound,
                    roleId: IdentityAssociationConstants.GroupMemberId));

            var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
            var groupRtIds = associations.Items
                .Where(a => a.OriginCkTypeId == groupCkTypeId)
                .Select(a => a.OriginRtId)
                .ToList();

            var groupNames = new List<string>();
            foreach (var groupRtId in groupRtIds)
            {
                var group = await tenantRepository.GetRtEntityByRtIdAsync<RtGroup>(session, groupRtId);
                if (group != null)
                {
                    groupNames.Add(group.GroupName);
                }
            }

            groupNamesByMappingId[mapping.RtId.ToString()] = groupNames;
        }

        await session.CommitTransactionAsync();

        return Ok(result.Items.Select(m => MapToDto(m,
            groupNamesByMappingId.GetValueOrDefault(m.RtId.ToString()) ?? [])));
    }

    /// <summary>
    /// Creates a new external tenant user mapping in the target tenant.
    /// </summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new external tenant user mapping in the target tenant.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> Create(
        [Required] string targetTenantId,
        [Required][FromBody][Description("The mapping data")] CreateExternalTenantUserMappingDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
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

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();
        await tenantRepository.InsertOneRtEntityAsync(session, mapping);
        await session.CommitTransactionAsync();

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, targetTenantId, dto.SourceTenantId);

        return Created(string.Empty, MapToDto(mapping, []));
    }

    /// <summary>
    /// Provisions the current user in the target tenant with all available roles.
    /// </summary>
    [HttpPost("provisionCurrentUser")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Provisions the current user in the target tenant with all roles.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> ProvisionCurrentUser(
        [Required] string targetTenantId)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
        }

        // Extract user info from claims — check both unmapped (sub, preferred_username)
        // and mapped (ClaimTypes.NameIdentifier, ClaimTypes.Name) variants because
        // JwtBearerOptions.MapInboundClaims may remap JWT claims to XML namespace URIs.
        var userId = HttpContext.User.FindFirstValue(JwtClaimTypes.Subject)
                     ?? HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var tenantId = HttpContext.User.FindFirstValue("tenant_id");

        if (string.IsNullOrEmpty(userId))
        {
            return BadRequest("Cannot determine user identity from token.");
        }

        if (string.IsNullOrEmpty(tenantId))
        {
            return BadRequest("Cannot determine source tenant from token.");
        }

        // Access tokens typically don't include profile claims (name, preferred_username).
        // Try claims first, then fall back to looking up the user from the source tenant.
        var userName = HttpContext.User.FindFirstValue(JwtClaimTypes.PreferredUserName)
                       ?? HttpContext.User.FindFirstValue(JwtClaimTypes.Name)
                       ?? HttpContext.User.FindFirstValue(ClaimTypes.Name);

        if (string.IsNullOrEmpty(userName))
        {
            var sourceTenantRepository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
            if (sourceTenantRepository != null)
            {
                var sourceSession = await sourceTenantRepository.GetSessionAsync();
                var user = await sourceTenantRepository
                    .GetRtEntityByRtIdAsync<RtUser>(sourceSession, new OctoObjectId(userId));
                userName = user?.UserName ?? userId;
            }
            else
            {
                userName = userId;
            }
        }

        // The target tenant may still be initializing (CK model import + default-configuration
        // seeding run asynchronously after tenant creation). Retry with backoff while the tenant is
        // not ready, and once the budget is exhausted surface a clean 503 — not a generic 500.
        const int maxRetries = 10;
        const int retryDelayMs = 1000;
        for (var attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                return await ProvisionCurrentUserInternal(tenantRepository, userId, userName, tenantId);
            }
            catch (Exception ex) when (IsTenantInitializing(ex))
            {
                logger.LogInformation(ex,
                    "Target tenant '{TargetTenantId}' is not ready yet (attempt {Attempt}/{MaxRetries}).",
                    targetTenantId, attempt, maxRetries);

                // On the final attempt do NOT rethrow — the previous code's `attempt < maxRetries`
                // guard let the last not-ready failure bubble up as a 500 (AB#4348). Return 503 so
                // the operator/CLI gets an actionable "still initializing" signal instead.
                if (attempt >= maxRetries)
                {
                    return StatusCode(StatusCodes.Status503ServiceUnavailable,
                        $"Tenant '{targetTenantId}' is still initializing. Please try again shortly.");
                }

                await Task.Delay(retryDelayMs * attempt);
            }
        }

        // Unreachable — the loop either returns a mapping or the 503 above — but the compiler needs
        // a terminal return.
        return StatusCode(StatusCodes.Status503ServiceUnavailable,
            $"Tenant '{targetTenantId}' is still initializing. Please try again shortly.");
    }

    /// <summary>
    /// Returns true when an exception indicates the target tenant is still being provisioned and the
    /// provisioning should be retried: an unpopulated CK cache (<see cref="CkCacheException"/>), missing
    /// default configuration / roles (<see cref="TenantNotReadyException"/>), or a freshly-provisioned
    /// identity database whose first read fails with MongoDB errorCode 13 ("requires authentication")
    /// because the tenant database user is not yet in place (AB#4348). Walks the inner-exception chain so
    /// wrapped failures are matched too.
    /// </summary>
    private static bool IsTenantInitializing(Exception exception)
    {
        for (Exception? ex = exception; ex is not null; ex = ex.InnerException)
        {
            if (ex is CkCacheException or TenantNotReadyException)
            {
                return true;
            }

            if (ex is MongoDB.Driver.MongoCommandException { Code: 13 })
            {
                return true;
            }
        }

        return false;
    }

    private async Task<ActionResult<ExternalTenantUserMappingDto>> ProvisionCurrentUserInternal(
        ITenantRepository tenantRepository, string userId, string userName, string tenantId)
    {
        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        // Check if mapping already exists
        var existingQuery = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), tenantId)
            .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), userId);
        var existingResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, existingQuery);

        if (existingResult.Items.Any())
        {
            var existingMapping = existingResult.Items.First();

            // Resolve group names for existing mapping
            var existingAssociations = await tenantRepository.GetRtAssociationsAsync(
                session,
                existingMapping.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(
                    GraphDirections.Inbound,
                    roleId: IdentityAssociationConstants.GroupMemberId));

            var existingGroupNames = new List<string>();
            var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
            foreach (var assoc in existingAssociations.Items.Where(a => a.OriginCkTypeId == groupCkTypeId))
            {
                var g = await tenantRepository.GetRtEntityByRtIdAsync<RtGroup>(session, assoc.OriginRtId);
                if (g != null) existingGroupNames.Add(g.GroupName);
            }

            await session.CommitTransactionAsync();
            return Ok(MapToDto(existingMapping, existingGroupNames));
        }

        // Get all roles from target tenant.
        // If no roles exist yet, the default configuration has not been initialized —
        // throw to trigger a retry in the caller.
        var roleResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        if (!roleResult.Items.Any())
        {
            await session.CommitTransactionAsync();
            throw new TenantNotReadyException("No roles found in target tenant — default configuration not yet initialized.");
        }

        var roleIds = roleResult.Items.Select(r => r.RtId.ToString()).ToList();

        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = tenantId,
            SourceUserId = userId,
            SourceUserName = userName,
            MappedRoleIds = new AttributeStringValueList(roleIds)
        };

        await tenantRepository.InsertOneRtEntityAsync(session, mapping);

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, tenantRepository.TenantId, tenantId);

        // Add mapping as member of TenantOwners group
        var groupNames = new List<string>();
        var groupQuery = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName),
                CommonConstants.TenantOwnersGroup.ToUpperInvariant());
        var groupResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtGroup>(session, groupQuery);
        var tenantOwnersGroup = groupResult.Items.FirstOrDefault();

        if (tenantOwnersGroup != null)
        {
            var updates = new List<AssociationUpdateInfo>
            {
                AssociationUpdateInfo.CreateInsert(
                    tenantOwnersGroup.ToRtEntityId(),
                    mapping.ToRtEntityId(),
                    IdentityAssociationConstants.GroupMemberId)
            };
            var opResult = new OperationResult();
            await tenantRepository.ApplyChangesAsync(session, updates, opResult);
            groupNames.Add(tenantOwnersGroup.GroupName);
        }

        await session.CommitTransactionAsync();

        return Created(string.Empty, MapToDto(mapping, groupNames));
    }

    /// <summary>
    /// Deletes an external tenant user mapping in the target tenant.
    /// </summary>
    [HttpDelete("{mappingRtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes an external tenant user mapping in the target tenant.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(
        [Required] string targetTenantId,
        [Required] OctoObjectId mappingRtId)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
        }

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existing = await tenantRepository
            .GetRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mappingRtId);
        if (existing == null)
        {
            await session.CommitTransactionAsync();
            return NotFound($"Mapping '{mappingRtId}' not found in tenant '{targetTenantId}'.");
        }

        await tenantRepository
            .DeleteOneRtEntityByRtIdAsync<RtExternalTenantUserMapping>(session, mappingRtId, DeleteOptions.Erase);
        await session.CommitTransactionAsync();

        return Ok();
    }

    /// <summary>
    /// Ensures the OctoTenantIdentityProvider exists in the target tenant, pointing to the source tenant.
    /// This enables "LOGIN VIA {sourceTenant}" on the target tenant's login page.
    /// </summary>
    private async Task EnsureOctoTenantIdentityProviderAsync(
        ITenantRepository tenantRepository, string targetTenantId, string sourceTenantId)
    {
        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existingResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(session, RtEntityQueryOptions.Create());

        if (existingResult.Items.Any(p =>
                string.Equals(p.ParentTenantId, sourceTenantId, StringComparison.OrdinalIgnoreCase)))
        {
            await session.CommitTransactionAsync();
            return;
        }

        var provider = new RtOctoTenantIdentityProvider
        {
            Name = $"ParentTenant_{sourceTenantId}",
            IsEnabled = true,
            DisplayName = $"Login via {sourceTenantId}",
            ParentTenantId = sourceTenantId
        };

        await tenantRepository.InsertOneRtEntityAsync(session, provider);
        await session.CommitTransactionAsync();

        // Refresh auth schemes so the new provider is immediately available
        await dynamicAuthSchemeService.ConfigureAsync(targetTenantId);

        logger.LogInformation(
            "Created OctoTenantIdentityProvider in tenant '{TargetTenantId}' pointing to '{SourceTenantId}'",
            targetTenantId, sourceTenantId);
    }

    private static ExternalTenantUserMappingDto MapToDto(
        RtExternalTenantUserMapping mapping, List<string> groupNames) =>
        new()
        {
            Id = mapping.RtId,
            SourceTenantId = mapping.SourceTenantId,
            SourceUserId = mapping.SourceUserId,
            SourceUserName = mapping.SourceUserName,
            RoleIds = mapping.MappedRoleIds?.ToList() ?? [],
            GroupNames = groupNames
        };
}

/// <summary>
/// Thrown when the target tenant's default configuration (roles, groups) is not yet initialized.
/// </summary>
internal class TenantNotReadyException(string message) : Exception(message);
