using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Asp.Versioning;
using Duende.IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.AdminProvisioning;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Services.RestDeprecation;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for pre-provisioning cross-tenant user mappings in a target tenant.
/// Routed via the caller's tenant so that the calling user does not need allowed_tenants for the target tenant.
/// Requires TenantManagement or UserManagement, and the target must be the caller's own tenant or
/// one of its descendants (<see cref="AdminProvisioningTargetScopeFilter"/>, again in the method handlers).
/// Every write is a facade of a static <c>ExternalTenantUserMapping</c> method (docs/identity-rest-facades.md); the
/// reads stay REST reads.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[TypeFilter(typeof(AdminProvisioningTargetScopeFilter))]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]/{targetTenantId}")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class AdminProvisioningController(
    ISystemContext systemContext,
    ICrossTenantAncestryGuard ancestryGuard,
    IIdentityMethodFacade methodFacade) : ControllerBase
{
    /// <summary>
    /// Response header of <c>provisionCurrentUser</c> that tells what the call did:
    /// <see cref="OutcomeCreated"/>, <see cref="OutcomeRepaired"/> or <see cref="OutcomeAlreadyProvisioned"/>.
    /// </summary>
    public const string ProvisioningOutcomeHeader = "X-Provisioning-Outcome";

    /// <summary>No mapping existed; one with all target roles and TenantOwners membership was created.</summary>
    public const string OutcomeCreated = AdminProvisioningService.OutcomeCreated;

    /// <summary>A mapping existed but granted no effective role (or carried a wrong user name); it was fixed.</summary>
    public const string OutcomeRepaired = AdminProvisioningService.OutcomeRepaired;

    /// <summary>A mapping with an effective role and the right user name existed; nothing was changed.</summary>
    public const string OutcomeAlreadyProvisioned = AdminProvisioningService.OutcomeAlreadyProvisioned;

    /// <summary>
    /// Returns all external tenant user mappings in the target tenant.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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
    /// Creates a new external tenant user mapping in the target tenant. Facade of the CK method
    /// <c>ExternalTenantUserMapping.ProvisionAdmin-1</c>.
    /// </summary>
    [HttpPost]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.AdminProvisioningMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a new external tenant user mapping in the target tenant.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> Create(
        [Required] string targetTenantId,
        [Required][FromBody][Description("The mapping data")] CreateExternalTenantUserMappingDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId, null,
            new ExternalTenantUserMappingProvisionAdminParameters
            {
                TargetTenantId = targetTenantId,
                SourceTenantId = dto.SourceTenantId,
                SourceUserId = dto.SourceUserId,
                SourceUserName = dto.SourceUserName,
                RoleIds = dto.RoleIds?.ToList()
            }, User, HttpContext.RequestAborted);
        return WriteResult(response, targetTenantId, dto.SourceTenantId, dto.SourceUserId);
    }

    /// <summary>
    /// Provisions the current user in the target tenant with all available roles. Idempotent and self-healing:
    /// 201 + <c>X-Provisioning-Outcome: created</c> for a new mapping; 200 + <c>repaired</c> when a
    /// mapping existed but granted no effective role or carried a wrong user name; 200 +
    /// <c>already-provisioned</c> when nothing needed to change. Facade of the CK method
    /// <c>ExternalTenantUserMapping.ProvisionCurrentUser-1</c>.
    /// <para>
    /// When the caller is a cross-tenant shadow user (<c>xt_…</c>, e.g. a session scoped to an
    /// intermediate tenant A that provisions into grandchild B), the mapping is written for the caller's
    /// <b>home identity</b> — the root of its <c>xt_</c> chain — not for the shadow user. The token exchange
    /// accepts a home mapping for every path of the same person (from the home tenant directly and from the
    /// shadow in A), while a shadow-keyed mapping is never found by an exchange from the home token. A shadow
    /// user whose home identity cannot be resolved is refused with 409 and nothing is written (fail closed).
    /// The response body names the identity the mapping was written for.
    /// </para>
    /// </summary>
    [HttpPost("provisionCurrentUser")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.AdminProvisioningMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Provisions the current user in the target tenant with all roles.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> ProvisionCurrentUser(
        [Required] string targetTenantId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId, null,
            new ExternalTenantUserMappingProvisionCurrentUserParameters { TargetTenantId = targetTenantId }, User,
            HttpContext.RequestAborted);
        var options = CommonOptions(targetTenantId)
            .MapSuccess(result =>
            {
                var record = ClientMirrorController.Deserialize<RtAdminProvisioningResultRecord>(result.ResultJson);
                Response.Headers[ProvisioningOutcomeHeader] = record.Outcome;
                return record.Outcome == OutcomeCreated
                    ? Created(string.Empty, MapToDto(record))
                    : Ok(MapToDto(record));
            })
            .MapError(AdminProvisioningMethodErrors.CallerNotAUser, error =>
                BadRequest(error.Parameters.GetValueOrDefault(AdminProvisioningMethodErrors.MissingParameter) == "tenant"
                    ? "Cannot determine source tenant from token."
                    : "Cannot determine user identity from token."))
            .MapError(AdminProvisioningMethodErrors.HomeIdentityUnresolved, _ =>
            {
                var callerName = User.FindFirstValue(JwtClaimTypes.PreferredUserName) ??
                                 User.FindFirstValue(JwtClaimTypes.Name) ?? User.FindFirstValue(ClaimTypes.Name) ??
                                 User.FindFirstValue(JwtClaimTypes.Subject) ?? "unknown";
                var tenantId = User.FindFirstValue("tenant_id");
                return Conflict(new ProblemDetails
                {
                    Status = StatusCodes.Status409Conflict,
                    Title = "Home identity of the cross-tenant user could not be resolved",
                    Detail = $"The caller '{callerName}' of tenant '{tenantId}' is a cross-tenant shadow user whose " +
                             "home identity could not be resolved, so no mapping was written. Sign in to the home " +
                             $"tenant of the user and run provisionCurrentUser for '{targetTenantId}' from there."
                });
            })
            .MapError(AdminProvisioningMethodErrors.TenantInitializing, _ =>
                StatusCode(StatusCodes.Status503ServiceUnavailable,
                    $"Tenant '{targetTenantId}' is still initializing. Please try again shortly."));
        return Unwrap(response.ToActionResult(options));
    }

    /// <summary>
    /// Deletes an external tenant user mapping in the target tenant. Facade of the CK method
    /// <c>ExternalTenantUserMapping.RemoveAdminProvisioning-1</c>.
    /// </summary>
    [HttpDelete("{mappingRtId}")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.AdminProvisioningMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Deletes an external tenant user mapping in the target tenant.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(
        [Required] string targetTenantId,
        [Required] OctoObjectId mappingRtId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId, null,
            new ExternalTenantUserMappingRemoveAdminProvisioningParameters
            {
                TargetTenantId = targetTenantId, MappingRtId = mappingRtId.ToString()
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(CommonOptions(targetTenantId)
            .MapSuccess(_ => Ok())
            .MapError(AdminProvisioningMethodErrors.MappingNotFound,
                _ => NotFound($"Mapping '{mappingRtId}' not found in tenant '{targetTenantId}'.")));
    }

    /// <summary>
    /// Searches candidate users from the target tenant's ancestor (parent) tenants — the users that
    /// may be provisioned as cross-tenant users into the target. Powers the Studio's user picker; no
    /// endpoint otherwise enumerates a parent tenant's directory, which is why a picker was impossible
    /// before. Matches on username OR email (case-insensitive, substring) and excludes cross-tenant
    /// shadow users (<c>xt_</c> prefix). An empty <paramref name="search"/> returns the first users.
    /// </summary>
    [HttpGet("sourceUsers")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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
    /// and mirrors how <see cref="ProvisionCurrentUser"/> grants access via the TenantOwners group. Facade of the CK
    /// method <c>ExternalTenantUserMapping.ProvisionAdminWithGroups-1</c>.
    /// </summary>
    [HttpPost("withGroups")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.AdminProvisioningMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a cross-tenant user mapping as a member of the given target-tenant groups.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<ExternalTenantUserMappingDto>> CreateWithGroups(
        [Required] string targetTenantId,
        [Required][FromBody][Description("The mapping data with target-tenant group ids")]
        CreateExternalTenantUserGroupMappingDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminWithGroupsMethodId, null,
            new ExternalTenantUserMappingProvisionAdminWithGroupsParameters
            {
                TargetTenantId = targetTenantId,
                SourceTenantId = dto.SourceTenantId,
                SourceUserId = dto.SourceUserId,
                SourceUserName = dto.SourceUserName,
                GroupIds = dto.GroupIds?.ToList()
            }, User, HttpContext.RequestAborted);
        return WriteResult(response, targetTenantId, dto.SourceTenantId, dto.SourceUserId);
    }

    /// <summary>The REST answer of a mapping create: 201 with the mapping, else the shared mappings.</summary>
    private ActionResult<ExternalTenantUserMappingDto> WriteResult(CkMethodResponse response, string targetTenantId,
        string sourceTenantId, string sourceUserId) =>
        Unwrap(response.ToActionResult(CommonOptions(targetTenantId)
            .MapSuccess(result => Created(string.Empty,
                MapToDto(ClientMirrorController.Deserialize<RtAdminProvisioningResultRecord>(result.ResultJson))))
            .MapError(AdminProvisioningMethodErrors.SourceTenantNotAncestor,
                _ => CrossTenantAncestryProblems.SourceTenantNotAncestor(targetTenantId, sourceTenantId))
            .MapError(AdminProvisioningMethodErrors.MappingAlreadyExists, error =>
                ExternalTenantUserMappingProblems.AlreadyExists(
                    error.Parameters.GetValueOrDefault(AdminProvisioningMethodErrors.ExistingMappingIdParameter) ??
                    string.Empty, sourceTenantId, sourceUserId))));

    /// <summary>
    /// The mappings every write shares: a target outside the caller's subtree the empty <c>403</c> of the scope filter, a
    /// missing target tenant the earlier <c>404</c> text. Other refusals keep the default <c>403</c> problem, a handler
    /// failure the default <c>500</c> problem.
    /// </summary>
    private CkMethodFacadeOptions CommonOptions(string targetTenantId) =>
        new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodForbidden, error =>
                error.Parameters.GetValueOrDefault("reason") == CrossTenantMethodSupport.TenantOutOfScopeReason
                    ? new ForbidResult()
                    : CkMethodFacadeResults.Problem(error, StatusCodes.Status403Forbidden))
            .MapError(AdminProvisioningMethodErrors.TenantNotFound, _ => NotFound($"Tenant '{targetTenantId}' not found."));

    private static ActionResult<ExternalTenantUserMappingDto> Unwrap(IActionResult result) =>
        result is ActionResult actionResult ? actionResult : new ObjectResult(result);

    /// <summary>
    /// The tenants whose users may be offered as cross-tenant sources of the target: the tenants the target's
    /// <see cref="RtOctoTenantIdentityProvider.ParentTenantId"/> chain reaches (breadth-first, cycle-safe,
    /// depth-capped) — the target's opt-in — and that the tenant registry confirms as ancestors of the target
    /// (AB#8339). Before AB#8339 the providers alone decided, so a provider the target's administrator pointed at
    /// any tenant opened that tenant's user directory. Under <c>CrossTenantAncestry=Warn</c> such a tenant is still
    /// returned and logged.
    /// </summary>
    private async Task<List<string>> ResolveAncestorTenantIdsAsync(string targetTenantId)
    {
        const int maxDepth = 10;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { targetTenantId };
        var reachable = new List<string>();
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
                        reachable.Add(provider.ParentTenantId);
                        frontier.Enqueue(provider.ParentTenantId);
                    }
                }
            }
        }

        if (reachable.Count == 0)
        {
            return reachable;
        }

        var registryAncestors = await ancestryGuard.GetRegistryAncestorsAsync(targetTenantId);
        return reachable
            .Where(tenantId => ancestryGuard.IsTrustedAncestor(targetTenantId, registryAncestors, tenantId,
                "provisioning source users"))
            .ToList();
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

    private static ExternalTenantUserMappingDto MapToDto(RtAdminProvisioningResultRecord record) =>
        new()
        {
            Id = OctoObjectId.Parse(record.MappingRtId),
            SourceTenantId = record.SourceTenantId,
            SourceUserId = record.SourceUserId,
            SourceUserName = record.SourceUserName,
            RoleIds = record.RoleIds?.ToList() ?? [],
            GroupNames = record.GroupNames?.ToList() ?? []
        };
}
