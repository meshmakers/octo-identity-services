using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Asp.Versioning;
using Duende.IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for pre-provisioning cross-tenant user mappings in a target tenant.
/// Routed via the system tenant so that the calling user does not need allowed_tenants for the target tenant.
/// AB#5859: requires TenantManagement or UserManagement, and the target must be the caller's own tenant or
/// one of its descendants (<see cref="AdminProvisioningTargetScopeFilter"/>).
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[TypeFilter(typeof(AdminProvisioningTargetScopeFilter))]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]/{targetTenantId}")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class AdminProvisioningController(
    ISystemContext systemContext,
    IDynamicAuthSchemeService dynamicAuthSchemeService,
    ICrossTenantShadowUserChainResolver shadowUserChainResolver,
    ILogger<AdminProvisioningController> logger) : ControllerBase
{
    /// <summary>
    /// Response header of <c>provisionCurrentUser</c> that tells what the call did (AB#7088):
    /// <see cref="OutcomeCreated"/>, <see cref="OutcomeRepaired"/> or <see cref="OutcomeAlreadyProvisioned"/>.
    /// </summary>
    public const string ProvisioningOutcomeHeader = "X-Provisioning-Outcome";

    /// <summary>No mapping existed; one with all target roles and TenantOwners membership was created.</summary>
    public const string OutcomeCreated = "created";

    /// <summary>A mapping existed but granted no effective role (or carried a wrong user name); it was fixed.</summary>
    public const string OutcomeRepaired = "repaired";

    /// <summary>A mapping with an effective role and the right user name existed; nothing was changed.</summary>
    public const string OutcomeAlreadyProvisioned = "already-provisioned";

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
    /// Creates a new external tenant user mapping in the target tenant.
    /// </summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a new external tenant user mapping in the target tenant.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
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

        // A mapping is unique per (source tenant, source user): a second one would lock the user out (AB#6975).
        var duplicate = await ExternalTenantUserMappingLookup.FindOldestAsync(
            tenantRepository, dto.SourceTenantId, dto.SourceUserId, logger);
        if (duplicate != null)
        {
            return ExternalTenantUserMappingProblems.AlreadyExists(duplicate, dto.SourceTenantId, dto.SourceUserId);
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

        // AB#8161: a mapping that carries TenantManagement is an administrator mapping: it joins TenantOwners
        // (which holds every role including SecretManagement) in addition to the roles it was created with.
        var groupNames = new List<string>();
        if (dto.RoleIds != null && await ContainsTenantManagementRoleAsync(tenantRepository, session, dto.RoleIds))
        {
            var tenantOwnersGroup = await FindTenantOwnersGroupAsync(tenantRepository, session);
            if (tenantOwnersGroup != null)
            {
                await AddToTenantOwnersGroupAsync(tenantRepository, session, tenantOwnersGroup, mapping);
                groupNames.Add(tenantOwnersGroup.GroupName);
            }
        }

        await session.CommitTransactionAsync();

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, targetTenantId, dto.SourceTenantId);

        return Created(string.Empty, MapToDto(mapping, groupNames));
    }

    /// <summary>
    /// Provisions the current user in the target tenant with all available roles. Idempotent and self-healing
    /// (AB#7088): 201 + <c>X-Provisioning-Outcome: created</c> for a new mapping; 200 + <c>repaired</c> when a
    /// mapping existed but granted no effective role or carried a wrong user name; 200 +
    /// <c>already-provisioned</c> when nothing needed to change.
    /// <para>
    /// AB#8017: when the caller is a cross-tenant shadow user (<c>xt_…</c>, e.g. a session scoped to an
    /// intermediate tenant A that provisions into grandchild B), the mapping is written for the caller's
    /// <b>home identity</b> — the root of its <c>xt_</c> chain — not for the shadow user. The token exchange
    /// accepts a home mapping for every path of the same person (from the home tenant directly and from the
    /// shadow in A), while a shadow-keyed mapping is never found by an exchange from the home token. A shadow
    /// user whose home identity cannot be resolved is refused with 409 and nothing is written (fail closed).
    /// The response body names the identity the mapping was written for.
    /// </para>
    /// </summary>
    [HttpPost("provisionCurrentUser")]
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
        // Try claims first, then fall back to the user stored in the source tenant.
        var claimUserName = HttpContext.User.FindFirstValue(JwtClaimTypes.PreferredUserName)
                            ?? HttpContext.User.FindFirstValue(JwtClaimTypes.Name)
                            ?? HttpContext.User.FindFirstValue(ClaimTypes.Name);
        var storedUserName = await FindUserNameByIdAsync(tenantId, userId);
        var userName = !string.IsNullOrEmpty(claimUserName) ? claimUserName : storedUserName ?? userId;

        // AB#8017: a shadow user (session scoped to an intermediate tenant) is provisioned as its home identity.
        // The stored name is authoritative; the claim only counts when the user cannot be read.
        var callerName = storedUserName ?? claimUserName;
        if (CrossTenantShadowUserName.IsShadowUserName(callerName))
        {
            var home = await ResolveHomeIdentityAsync(callerName!);
            if (home == null || string.Equals(home.Value.TenantId, targetTenantId, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning(
                    "ProvisionCurrentUser refused: caller '{CallerUserName}' of tenant '{CallerTenantId}' is a cross-tenant shadow user whose home identity could not be resolved (target tenant '{TargetTenantId}')",
                    callerName, tenantId, targetTenantId);
                return Conflict(new ProblemDetails
                {
                    Status = StatusCodes.Status409Conflict,
                    Title = "Home identity of the cross-tenant user could not be resolved",
                    Detail = $"The caller '{callerName}' of tenant '{tenantId}' is a cross-tenant shadow user whose " +
                             "home identity could not be resolved, so no mapping was written. Sign in to the home " +
                             $"tenant of the user and run provisionCurrentUser for '{targetTenantId}' from there."
                });
            }

            logger.LogInformation(
                "ProvisionCurrentUser: caller '{CallerUserName}' of tenant '{CallerTenantId}' is a cross-tenant shadow user; provisioning its home identity '{HomeUserName}' ({HomeUserId}) of tenant '{HomeTenantId}' into tenant '{TargetTenantId}'",
                callerName, tenantId, home.Value.UserName, home.Value.UserId, home.Value.TenantId, targetTenantId);

            tenantId = home.Value.TenantId;
            userId = home.Value.UserId;
            userName = home.Value.UserName;
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

    /// <summary>The user name stored for <paramref name="userId" /> in <paramref name="tenantId" />, or <c>null</c>.</summary>
    private async Task<string?> FindUserNameByIdAsync(string tenantId, string userId)
    {
        if (!OctoObjectId.TryParse(userId, out var userRtId))
        {
            return null;
        }

        var repository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        if (repository == null)
        {
            return null;
        }

        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var user = await repository.GetRtEntityByRtIdAsync<RtUser>(session, userRtId);
        await session.CommitTransactionAsync();
        return user?.UserName;
    }

    /// <summary>
    /// AB#8017: unwinds a shadow user name (<c>xt_{tenant}_{user}</c>, possibly nested) against the tenant
    /// registry to the root identity and looks that user up in its tenant. Returns <c>null</c> — fail closed —
    /// when the chain is ambiguous or broken (the last tier is still a shadow name), the home tenant is not
    /// registered or the home user does not exist.
    /// </summary>
    private async Task<(string TenantId, string UserId, string UserName)?> ResolveHomeIdentityAsync(
        string shadowUserName)
    {
        var chain = await shadowUserChainResolver.GetSourceChainAsync(shadowUserName);
        if (chain.Count == 0)
        {
            return null;
        }

        var (homeTenantId, homeUserName) = chain[^1];
        if (CrossTenantShadowUserName.IsShadowUserName(homeUserName))
        {
            return null;
        }

        var repository = await systemContext.TryFindTenantRepositoryAsync(homeTenantId);
        if (repository == null)
        {
            return null;
        }

        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtUser>(session,
            RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtUser.NormalizedUserName), homeUserName.ToUpperInvariant()));
        await session.CommitTransactionAsync();

        var homeUser = result.Items.FirstOrDefault();
        return homeUser == null
            ? null
            : (homeTenantId, homeUser.RtId.ToString(), homeUser.UserName ?? homeUserName);
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

        var existingMapping = ExternalTenantUserMappingLookup.PickOldest(
            existingResult.Items.ToList(), tenantId, userId, logger);

        // Get all roles from target tenant. Needed to fill a new mapping and to judge whether an existing
        // one grants anything. If no roles exist yet, the default configuration has not been initialized —
        // throw to trigger a retry in the caller.
        var roleResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create());
        if (!roleResult.Items.Any())
        {
            await session.CommitTransactionAsync();
            throw new TenantNotReadyException("No roles found in target tenant — default configuration not yet initialized.");
        }

        var roleIds = roleResult.Items.Select(r => r.RtId.ToString()).ToList();

        if (existingMapping != null)
        {
            return await RepairOrConfirmExistingMappingAsync(
                tenantRepository, session, existingMapping, roleIds, userId, userName, tenantId);
        }

        // AB#8161: an administrator is a TenantOwners member, not the holder of direct roles; the group carries
        // every role. A tenant without the group, or with a group that carries no role, keeps the role list.
        var tenantOwnersGroup = await FindTenantOwnersGroupAsync(tenantRepository, session);
        var groupCarriesRoles = tenantOwnersGroup != null
                                && await GroupHasRolesAsync(tenantRepository, session, tenantOwnersGroup);
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = tenantId,
            SourceUserId = userId,
            SourceUserName = userName,
            MappedRoleIds = groupCarriesRoles ? null : new AttributeStringValueList(roleIds)
        };

        await tenantRepository.InsertOneRtEntityAsync(session, mapping);

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, tenantRepository.TenantId, tenantId);

        // Add mapping as member of TenantOwners group
        var groupNames = new List<string>();
        if (tenantOwnersGroup != null)
        {
            await AddToTenantOwnersGroupAsync(tenantRepository, session, tenantOwnersGroup, mapping);
            groupNames.Add(tenantOwnersGroup.GroupName);
        }

        await session.CommitTransactionAsync();

        Response.Headers[ProvisioningOutcomeHeader] = OutcomeCreated;
        return Created(string.Empty, MapToDto(mapping, groupNames));
    }

    /// <summary>
    /// A mapping for (source tenant, source user) already exists (AB#7088). It only counts as provisioned when
    /// it grants an effective role and carries the user name the role lookup keys on: the token exchange
    /// resolves roles by source tenant + source user NAME, this lookup finds the mapping by user ID. A bare
    /// mapping (stored by the cross-tenant login before anybody provisioned the user), one that lists no
    /// existing role and is in no group with roles, or one with a wrong name leaves the user denied — it is
    /// repaired here instead of being reported as provisioned. A mapping that already grants a role is never
    /// widened: only a wrong name is corrected.
    /// </summary>
    private async Task<ActionResult<ExternalTenantUserMappingDto>> RepairOrConfirmExistingMappingAsync(
        ITenantRepository tenantRepository, IOctoSession session, RtExternalTenantUserMapping mapping,
        IReadOnlyList<string> targetRoleIds, string userId, string userName, string tenantId)
    {
        var targetRoleIdSet = targetRoleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Groups the mapping is a member of (names for the response, roles to judge the grant).
        var associations = await tenantRepository.GetRtAssociationsAsync(
            session,
            mapping.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Inbound,
                roleId: IdentityAssociationConstants.GroupMemberId));

        var groupNames = new List<string>();
        var groupRoleIds = new List<string>();
        var groupCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtGroup>();
        foreach (var assoc in associations.Items.Where(a => a.OriginCkTypeId == groupCkTypeId))
        {
            var group = await tenantRepository.GetRtEntityByRtIdAsync<RtGroup>(session, assoc.OriginRtId);
            if (group == null)
            {
                continue;
            }

            groupNames.Add(group.GroupName);

            var groupRoleAssociations = await tenantRepository.GetRtAssociationsAsync(
                session,
                group.ToRtEntityId(),
                RtAssociationExtendedQueryOptions.Create(
                    GraphDirections.Outbound,
                    roleId: IdentityAssociationConstants.AssignedRoleId));
            groupRoleIds.AddRange(groupRoleAssociations.Items.Select(a => a.TargetRtId.ToString()));
        }

        var grantsRole = (mapping.MappedRoleIds?.Any(targetRoleIdSet.Contains) ?? false)
                         || groupRoleIds.Any(targetRoleIdSet.Contains);

        // The user name only replaces a stored one when it is a real name; the user id is the fallback
        // used when the name could not be determined and must not overwrite a good name.
        var nameNeedsCorrection = !string.IsNullOrEmpty(userName)
                                  && !string.Equals(userName, userId, StringComparison.Ordinal)
                                  && !string.Equals(mapping.SourceUserName, userName, StringComparison.OrdinalIgnoreCase);

        if (grantsRole && !nameNeedsCorrection)
        {
            await session.CommitTransactionAsync();
            Response.Headers[ProvisioningOutcomeHeader] = OutcomeAlreadyProvisioned;
            return Ok(MapToDto(mapping, groupNames));
        }

        // AB#8161: repair through the TenantOwners group when it carries roles; the role list is the
        // fallback for a tenant without a usable group.
        var repairGroup = !grantsRole ? await FindTenantOwnersGroupAsync(tenantRepository, session) : null;
        var repairViaGroup = repairGroup != null && await GroupHasRolesAsync(tenantRepository, session, repairGroup);
        if (!grantsRole && !repairViaGroup)
        {
            mapping.MappedRoleIds = new AttributeStringValueList(targetRoleIds.ToList());
        }

        if (nameNeedsCorrection)
        {
            mapping.SourceUserName = userName;
        }

        await tenantRepository.ReplaceOneRtEntityByIdAsync(session, mapping.RtId, mapping);

        if (repairGroup != null && !grantsRole
            && !groupNames.Contains(CommonConstants.TenantOwnersGroup, StringComparer.OrdinalIgnoreCase))
        {
            await AddToTenantOwnersGroupAsync(tenantRepository, session, repairGroup, mapping);
            groupNames.Add(repairGroup.GroupName);
        }

        // Ensure OctoTenantIdentityProvider exists so cross-tenant login works
        await EnsureOctoTenantIdentityProviderAsync(tenantRepository, tenantRepository.TenantId, tenantId);

        await session.CommitTransactionAsync();

        logger.LogInformation(
            "Repaired external tenant user mapping '{MappingRtId}' of user '{SourceUserId}' from tenant '{SourceTenantId}' in tenant '{TargetTenantId}' (rolesFilled={RolesFilled}, nameCorrected={NameCorrected})",
            mapping.RtId, userId, tenantId, tenantRepository.TenantId, !grantsRole, nameNeedsCorrection);

        Response.Headers[ProvisioningOutcomeHeader] = OutcomeRepaired;
        return Ok(MapToDto(mapping, groupNames));
    }

    /// <summary>True when one of <paramref name="roleIds"/> is the TenantManagement role of the target tenant.</summary>
    private static async Task<bool> ContainsTenantManagementRoleAsync(
        ITenantRepository tenantRepository, IOctoSession session, IEnumerable<string> roleIds)
    {
        var roles = await tenantRepository.GetRtEntitiesByTypeAsync<RtRole>(
            session,
            RtEntityQueryOptions.Create().FieldEquals(
                nameof(RtRole.NormalizedName), CommonConstants.TenantManagementRole.ToUpperInvariant()));
        var tenantManagement = roles.Items.FirstOrDefault();
        return tenantManagement != null
               && roleIds.Contains(tenantManagement.RtId.ToString(), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>True when the group has at least one <c>AssignedRole</c> edge (otherwise it grants nothing).</summary>
    private static async Task<bool> GroupHasRolesAsync(
        ITenantRepository tenantRepository, IOctoSession session, RtGroup group)
    {
        var edges = await tenantRepository.GetRtAssociationsAsync(
            session,
            group.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        return edges.Items.Any();
    }

    /// <summary>The TenantOwners group of the target tenant, or <c>null</c> when the tenant has none.</summary>
    private static async Task<RtGroup?> FindTenantOwnersGroupAsync(
        ITenantRepository tenantRepository, IOctoSession session)
    {
        var groupQuery = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtGroup.NormalizedGroupName),
                CommonConstants.TenantOwnersGroup.ToUpperInvariant());
        var groupResult = await tenantRepository
            .GetRtEntitiesByTypeAsync<RtGroup>(session, groupQuery);
        return groupResult.Items.FirstOrDefault();
    }

    /// <summary>Adds the mapping to the given TenantOwners group as a member.</summary>
    private static async Task AddToTenantOwnersGroupAsync(
        ITenantRepository tenantRepository, IOctoSession session, RtGroup tenantOwnersGroup,
        RtExternalTenantUserMapping mapping)
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
    }

    /// <summary>
    /// Deletes an external tenant user mapping in the target tenant.
    /// </summary>
    [HttpDelete("{mappingRtId}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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
    /// and mirrors how <see cref="ProvisionCurrentUser"/> grants access via the TenantOwners group.
    /// </summary>
    [HttpPost("withGroups")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a cross-tenant user mapping as a member of the given target-tenant groups.")]
    [ProducesResponseType(typeof(ExternalTenantUserMappingDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
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

        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(targetTenantId);
        if (tenantRepository == null)
        {
            return NotFound($"Tenant '{targetTenantId}' not found.");
        }

        // A mapping is unique per (source tenant, source user): a second one would lock the user out (AB#6975).
        var duplicate = await ExternalTenantUserMappingLookup.FindOldestAsync(
            tenantRepository, dto.SourceTenantId, dto.SourceUserId, logger);
        if (duplicate != null)
        {
            return ExternalTenantUserMappingProblems.AlreadyExists(duplicate, dto.SourceTenantId, dto.SourceUserId);
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
