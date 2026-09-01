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
using Meshmakers.Octo.Backend.Authentication;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for pre-provisioning cross-tenant user mappings in a target tenant.
/// Routed via the system tenant so that the calling user does not need allowed_tenants for the target tenant.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
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
    /// Searches candidate users from the target tenant's ancestor (parent) tenants — the users that
    /// may be provisioned as cross-tenant users into the target. Powers the Studio's user picker; no
    /// endpoint otherwise enumerates a parent tenant's directory, which is why a picker was impossible
    /// before. Matches on username OR email (case-insensitive, substring) and excludes cross-tenant
    /// shadow users (<c>xt_</c> prefix). An empty <paramref name="search"/> returns the first users.
    /// </summary>
    [HttpGet("sourceUsers")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Searches provisionable users from the target tenant's ancestor tenants.")]
    [ProducesResponseType(typeof(IEnumerable<ProvisioningSourceUserDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IEnumerable<ProvisioningSourceUserDto>>> GetSourceUsers(
        [Required] string targetTenantId,
        [FromQuery] string? search = null,
        [FromQuery] int take = 20)
    {
        var targetRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (targetRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
        }

        take = Math.Clamp(take, 1, 100);

        var ancestorTenantIds = await ResolveAncestorTenantIdsAsync(targetTenantId);
        if (ancestorTenantIds.Count == 0)
        {
            return Ok(Enumerable.Empty<ProvisioningSourceUserDto>());
        }

        var results = new List<ProvisioningSourceUserDto>();
        foreach (var ancestorTenantId in ancestorTenantIds)
        {
            results.AddRange(await SearchUsersInTenantAsync(ancestorTenantId, search, take));
            if (results.Count >= take)
            {
                break;
            }
        }

        return Ok(results.Take(take));
    }

    /// <summary>
    /// Returns the roles defined in the target tenant so the Studio can offer them as assignable
    /// options when creating a cross-tenant user mapping. Read directly from the target tenant DB via
    /// the system context (the caller need not have <c>allowed_tenants</c> for the target).
    /// </summary>
    [HttpGet("roles")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Returns the roles defined in the target tenant.")]
    [ProducesResponseType(typeof(IEnumerable<ProvisioningRoleDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IEnumerable<ProvisioningRoleDto>>> GetRoles(
        [Required] string targetTenantId)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
        }

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();
        var roleResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();

        return Ok(roleResult.Items
            .Select(r => new ProvisioningRoleDto { Id = r.RtId.ToString(), Name = r.Name }));
    }

    /// <summary>
    /// Returns the groups defined in the target tenant, offered as assignable options when creating a
    /// cross-tenant user mapping. Assigning a group makes the mapping a GroupMember so the user inherits
    /// the group's roles — the idiomatic, group-based grant.
    /// </summary>
    [HttpGet("groups")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Returns the groups defined in the target tenant.")]
    [ProducesResponseType(typeof(IEnumerable<ProvisioningGroupDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IEnumerable<ProvisioningGroupDto>>> GetGroups(
        [Required] string targetTenantId)
    {
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
        }

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();
        var groupResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtGroup>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();

        return Ok(groupResult.Items.Select(g => new ProvisioningGroupDto
        {
            Id = g.RtId.ToString(),
            Name = g.GroupName,
            Description = g.GroupDescription
        }));
    }

    /// <summary>
    /// Creates a cross-tenant user mapping and makes it a member of the given target-tenant groups, so
    /// the user inherits the groups' roles. This is the group-based counterpart of <see cref="Create"/>
    /// and mirrors how <see cref="ProvisionCurrentUser"/> grants access via the TenantOwners group.
    /// </summary>
    [HttpPost("withGroups")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a cross-tenant user mapping as a member of the given target-tenant groups.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> CreateWithGroups(
        [Required] string targetTenantId,
        [Required][FromBody][Description("The mapping data with target-tenant group ids")]
        CreateExternalTenantUserGroupMappingDto dto)
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
            MappedRoleIds = null
        };

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();
        await tenantRepository.InsertOneRtEntityAsync(session, mapping);

        var groupNames = new List<string>();
        if (dto.GroupIds is { Count: > 0 })
        {
            var updates = new List<AssociationUpdateInfo>();
            foreach (var groupId in dto.GroupIds)
            {
                var group = await tenantRepository
                    .GetRtEntityByRtIdAsync<RtGroup>(session, new OctoObjectId(groupId));
                if (group == null)
                {
                    continue;
                }

                updates.Add(AssociationUpdateInfo.CreateInsert(
                    group.ToRtEntityId(),
                    mapping.ToRtEntityId(),
                    IdentityAssociationConstants.GroupMemberId));
                groupNames.Add(group.GroupName);
            }

            if (updates.Count > 0)
            {
                await tenantRepository.ApplyChangesAsync(session, updates, new OperationResult());
            }
        }

        await session.CommitTransactionAsync();

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, targetTenantId, dto.SourceTenantId);

        return Created(string.Empty, MapToDto(mapping, groupNames));
    }

    /// <summary>
    /// Walks the target tenant's ancestor chain via <see cref="RtOctoTenantIdentityProvider.ParentTenantId"/>
    /// (breadth-first, cycle-safe, depth-capped) and returns every ancestor tenant id. These are the only
    /// tenants a cross-tenant mapping's SourceTenantId may legitimately reference.
    /// </summary>
    private async Task<List<string>> ResolveAncestorTenantIdsAsync(string targetTenantId)
    {
        const int maxDepth = 10;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { targetTenantId };
        var ancestors = new List<string>();
        var frontier = new Queue<string>();
        frontier.Enqueue(targetTenantId);

        for (var depth = 0; depth < maxDepth && frontier.Count > 0; depth++)
        {
            var levelSize = frontier.Count;
            for (var i = 0; i < levelSize; i++)
            {
                var tenantId = frontier.Dequeue();
                var repository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
                if (repository == null)
                {
                    continue;
                }

                var session = await repository.GetSessionAsync();
                session.StartTransaction();
                var providers = await repository
                    .GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(session, RtEntityQueryOptions.Create());
                await session.CommitTransactionAsync();

                foreach (var provider in providers.Items)
                {
                    if (!string.IsNullOrEmpty(provider.ParentTenantId) && visited.Add(provider.ParentTenantId))
                    {
                        ancestors.Add(provider.ParentTenantId);
                        frontier.Enqueue(provider.ParentTenantId);
                    }
                }
            }
        }

        return ancestors;
    }

    /// <summary>
    /// Searches a single (ancestor) tenant's real users by username or email, excluding
    /// <c>xt_</c> shadow users. An empty search returns the first users of the tenant.
    /// </summary>
    private async Task<List<ProvisioningSourceUserDto>> SearchUsersInTenantAsync(
        string tenantId, string? search, int take)
    {
        var repository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        if (repository == null)
        {
            return [];
        }

        var session = await repository.GetSessionAsync();
        session.StartTransaction();

        var users = new List<RtUser>();
        if (string.IsNullOrWhiteSpace(search))
        {
            var allOptions = RtEntityQueryOptions.Create();
            var allResult = await repository
                .GetRtEntitiesByTypeAsync<RtUser>(session, allOptions, 0, take * 2);
            users.AddRange(allResult.Items);
        }
        else
        {
            var normalized = search.Trim().ToUpperInvariant();

            var byNameOptions = RtEntityQueryOptions.Create();
            byNameOptions.FieldContains(nameof(RtUser.NormalizedUserName), normalized);
            var byNameResult = await repository
                .GetRtEntitiesByTypeAsync<RtUser>(session, byNameOptions, 0, take * 2);
            users.AddRange(byNameResult.Items);

            var byEmailOptions = RtEntityQueryOptions.Create();
            byEmailOptions.FieldContains(nameof(RtUser.NormalizedEmail), normalized);
            var byEmailResult = await repository
                .GetRtEntitiesByTypeAsync<RtUser>(session, byEmailOptions, 0, take * 2);
            users.AddRange(byEmailResult.Items);
        }

        await session.CommitTransactionAsync();

        return users
            .Where(u => u.UserName == null || !u.UserName.StartsWith("xt_", StringComparison.OrdinalIgnoreCase))
            .GroupBy(u => u.RtId.ToString())
            .Select(g => g.First())
            .Select(u => new ProvisioningSourceUserDto
            {
                SourceTenantId = tenantId,
                UserId = u.RtId.ToString(),
                UserName = u.UserName ?? string.Empty,
                Email = u.Email,
                FirstName = u.FirstName,
                LastName = u.LastName
            })
            .Take(take)
            .ToList();
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
