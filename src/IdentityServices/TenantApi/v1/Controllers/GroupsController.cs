using System.Text.Json;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Microsoft.AspNetCore.Identity;
using Meshmakers.Octo.Services.Methods.Facades;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Methods;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for managing groups with role assignments.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class GroupsController(
    IGroupStore groupStore,
    IRoleChangeRefusals roleChangeRefusals,
    IIdentityMethodFacade methodFacade,
    RoleManager<RtRole> roleManager) : ControllerBase
{
    /// <summary>
    /// Returns all groups.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns all groups.")]
    [ProducesResponseType(typeof(IEnumerable<GroupDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<GroupDto>>> GetAll()
    {
        var groups = await groupStore.GetAllAsync();
        var dtos = new List<GroupDto>();
        foreach (var group in groups)
        {
            dtos.Add(await MapToDtoAsync(group));
        }

        return Ok(dtos);
    }

    /// <summary>
    /// Returns groups with pagination.
    /// </summary>
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns groups with pagination.")]
    [ProducesResponseType(typeof(IEnumerable<GroupDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<GroupDto>>> GetPaged(
        [FromQuery] int? skip = null,
        [FromQuery] int? take = null)
    {
        var groups = await groupStore.GetAllAsync(skip, take);
        var dtos = new List<GroupDto>();
        foreach (var group in groups)
        {
            dtos.Add(await MapToDtoAsync(group));
        }

        return Ok(dtos);
    }

    /// <summary>
    /// Returns a specific group by ID.
    /// </summary>
    [HttpGet("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns a group by its ID.")]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<GroupDto>> GetById([Required] OctoObjectId rtId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        return Ok(await MapToDtoAsync(group));
    }

    /// <summary>
    /// Returns a group by its name.
    /// </summary>
    [HttpGet("names/{groupName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns a group by its name.")]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<GroupDto>> GetByName([Required] string groupName)
    {
        var group = await groupStore.FindByNameAsync(groupName.ToUpperInvariant());
        if (group == null)
        {
            return NotFound();
        }

        return Ok(await MapToDtoAsync(group));
    }

    /// <summary>
    /// Creates a new group. Facade of the static CK method <c>Group.CreateGroup-1</c>.
    /// </summary>
    /// <remarks>
    /// The endpoint resolves the initial role ids to names (an unknown id is <c>404</c> and creates nothing) and calls
    /// <c>Group.CreateGroup</c> in-process: duplicate name, initial roles through the role change guard, write, one
    /// <c>Identity.Method</c> event. A refused initial role is the audited 403 problem of the guard.
    /// </remarks>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Creates a new group.")]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Create(
        [Required][FromBody][Description("The group data")] CreateGroupDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var roleIdsByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var roleId in dto.RoleIds ?? [])
        {
            var role = OctoObjectId.TryParse(roleId, out _) ? await roleManager.FindByIdAsync(roleId) : null;
            if (role == null)
            {
                return NotFound(new NotFoundErrorDto($"Role with id '{roleId}' not found."));
            }

            roleIdsByName[role.Name ?? role.RtId.ToString()] = roleId;
        }

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupCreateGroupMethodId, null,
            new GroupCreateGroupParameters
            {
                GroupName = dto.GroupName,
                GroupDescription = dto.GroupDescription,
                RoleNames = roleIdsByName.Count > 0 ? roleIdsByName.Keys.ToList() : null
            }, User, HttpContext.RequestAborted);
        if (RoleChangeProblems.RefusalOf(response) is { } decision)
        {
            return await roleChangeRefusals.RefuseAsync(HttpContext, RoleChangeCaller.FromPrincipal(User), decision,
                $"new group {dto.GroupName}");
        }

        if (response.Success)
        {
            var rtId = response.ResultJson == null ? null : JsonSerializer.Deserialize<string>(response.ResultJson);
            var group = rtId != null && OctoObjectId.TryParse(rtId, out var groupRtId)
                ? await groupStore.FindByIdAsync(groupRtId)
                : null;
            return group == null
                ? StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(CreateFailedMessage))
                : StatusCode(StatusCodes.Status201Created, await MapToDtoAsync(group));
        }

        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapError(IdentityCrudErrors.GroupAlreadyExists,
                _ => Conflict($"A group with name '{dto.GroupName}' already exists."))
            .MapError(UserRoleMethodErrors.RoleNotFound, error => NotFound(new NotFoundErrorDto(
                $"Role with id '{RoleIdOf(error, roleIdsByName)}' not found.")))
            .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => StatusCode(StatusCodes.Status500InternalServerError,
                new InternalServerErrorDto(CreateFailedMessage))));
    }

    private const string CreateFailedMessage = "Creation of the group failed.";

    /// <summary>
    /// Updates an existing group's name and description. Facade of the CK method <c>Group.UpdateGroup-1</c>.
    /// </summary>
    [HttpPut("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Updates an existing group.")]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Update(
        [Required] OctoObjectId rtId,
        [Required][FromBody][Description("The updated group data")] UpdateGroupDto dto)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupUpdateGroupMethodId, rtId.ToString(),
            new GroupUpdateGroupParameters { GroupName = dto.GroupName, GroupDescription = dto.GroupDescription }, User,
            HttpContext.RequestAborted);
        if (response.Success)
        {
            var group = await groupStore.FindByIdAsync(rtId);
            return group == null ? NotFound() : Ok(await MapToDtoAsync(group));
        }

        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => NotFound())
            .MapError(IdentityCrudErrors.GroupAlreadyExists,
                _ => Conflict($"A group with name '{dto.GroupName}' already exists.")));
    }

    /// <summary>
    /// Deletes a group. Facade of the CK method <c>Group.DeleteGroup-1</c>.
    /// </summary>
    /// <remarks>Removing the last user administrator is the audited 409 problem of the role change guard, as before.</remarks>
    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Deletes a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete([Required] OctoObjectId rtId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupDeleteGroupMethodId, rtId.ToString(), new GroupDeleteGroupParameters(), User,
            HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions());
    }
    // ========================================
    // Role assignments
    // ========================================

    /// <summary>
    /// Gets the role IDs assigned to a group.
    /// </summary>
    [HttpGet("{rtId}/roles")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Gets the role IDs assigned to a group.")]
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<List<string>>> GetRoles([Required] OctoObjectId rtId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        var roleIds = await groupStore.GetRoleIdsAsync(rtId);
        return Ok(roleIds.ToList());
    }

    /// <summary>
    /// Replaces the role assignments for a group. Facade of the CK method <c>Group.SetRoles-1</c>.
    /// </summary>
    /// <remarks>
    /// The endpoint resolves the role ids to names (an unknown id is <c>404</c> and changes nothing) and calls
    /// <c>Group.SetRoles</c> in-process: role change guard, write, one <c>Identity.Method</c> audit event.
    /// </remarks>
    [HttpPut("{rtId}/roles")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Replaces the role assignments for a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateRoles(
        [Required] OctoObjectId rtId,
        [Required][FromBody] List<string> roleIds)
    {
        // REST names the roles by id, the method by name: resolve every id first, so an unknown id changes nothing.
        var roleIdsByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var roleId in roleIds)
        {
            var role = OctoObjectId.TryParse(roleId, out _) ? await roleManager.FindByIdAsync(roleId) : null;
            if (role == null)
            {
                return NotFound(new NotFoundErrorDto($"Role with id '{roleId}' not found."));
            }

            roleIdsByName[role.Name ?? role.RtId.ToString()] = roleId;
        }

        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupSetRolesMethodId, rtId.ToString(),
            new GroupSetRolesParameters { RoleNames = roleIdsByName.Keys.ToList() }, User, HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions()
            .MapError(UserRoleMethodErrors.RoleNotFound, error => NotFound(new NotFoundErrorDto(
                $"Role with id '{RoleIdOf(error, roleIdsByName)}' not found."))));
    }

    // ========================================
    // User members
    // ========================================

    /// <summary>
    /// Gets the user member IDs of a group.
    /// </summary>
    [HttpGet("{rtId}/members/users")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Gets the user member IDs of a group.")]
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<List<string>>> GetUserMembers([Required] OctoObjectId rtId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        var memberUserIds = await groupStore.GetMemberUserIdsAsync(rtId);
        return Ok(memberUserIds.ToList());
    }

    /// <summary>
    /// Adds a user to a group. Facade of the CK method <c>Group.AddMember-1</c> (member kind <c>User</c>).
    /// </summary>
    /// <remarks>A user that does not exist is <c>404</c>; a user that already is a member is <c>200</c> without a change.</remarks>
    [HttpPut("{rtId}/members/users/{userId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Adds a user to a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddUserMember(
        [Required] OctoObjectId rtId,
        [Required] string userId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupAddMemberMethodId, rtId.ToString(),
            new GroupAddMemberParameters { MemberKind = RtGroupMemberKindEnum.User, MemberId = userId }, User,
            HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions()
            .MapError(GroupMethodErrors.MemberNotFound, _ => UserNotFound(userId))
            .MapError(GroupMethodErrors.MemberAlreadyInGroup, _ => Ok()));
    }

    /// <summary>
    /// Removes a user from a group. Facade of the CK method <c>Group.RemoveMember-1</c> (member kind <c>User</c>).
    /// </summary>
    /// <remarks>A user that is not a member (or does not exist) is <c>200</c> without a change, as before.</remarks>
    [HttpDelete("{rtId}/members/users/{userId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Removes a user from a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveUserMember(
        [Required] OctoObjectId rtId,
        [Required] string userId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupRemoveMemberMethodId, rtId.ToString(),
            new GroupRemoveMemberParameters { MemberKind = RtGroupMemberKindEnum.User, MemberId = userId }, User,
            HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions()
            .MapError(GroupMethodErrors.MemberNotInGroup, _ => Ok())
            .MapError(GroupMethodErrors.MemberNotFound, _ => Ok()));
    }

    // ========================================
    // Client members
    // ========================================

    /// <summary>
    /// Gets the client member IDs of a group.
    /// </summary>
    [HttpGet("{rtId}/members/clients")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Gets the client member IDs of a group.")]
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<List<string>>> GetClientMembers([Required] OctoObjectId rtId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        var memberClientIds = await groupStore.GetMemberClientIdsAsync(rtId);
        return Ok(memberClientIds.ToList());
    }

    /// <summary>
    /// Adds a client to a group. The client is named by its OAuth client id or by its rtId. Facade of the CK
    /// method <c>Group.AddMember-1</c> (member kind <c>Client</c>).
    /// </summary>
    [HttpPut("{rtId}/members/clients/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Adds a client to a group.")]
    [EndpointDescription("The client is named by its OAuth client id or by its rtId. 404 when the group or the client does not exist.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddClientMember(
        [Required] OctoObjectId rtId,
        [Required] string clientId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupAddMemberMethodId, rtId.ToString(),
            new GroupAddMemberParameters { MemberKind = RtGroupMemberKindEnum.Client, MemberId = clientId }, User,
            HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions()
            .MapError(GroupMethodErrors.MemberNotFound, _ => ClientNotFound(clientId))
            .MapError(GroupMethodErrors.MemberAlreadyInGroup, _ => Ok()));
    }

    /// <summary>
    /// Removes a client from a group. The client is named by its OAuth client id or by its rtId. Facade of the
    /// CK method <c>Group.RemoveMember-1</c> (member kind <c>Client</c>).
    /// </summary>
    /// <remarks>
    /// An rtId of a client that no longer exists still removes its leftover membership edge, and an rtId that is no member
    /// is <c>200</c> without a change, as before; a client id that names no client is <c>404</c>. The method records the
    /// revocation of a scratch tenant's creator mirror before the membership goes.
    /// </remarks>
    [HttpDelete("{rtId}/members/clients/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Removes a client from a group.")]
    [EndpointDescription("The client is named by its OAuth client id or by its rtId. 404 when the group or the client does not exist.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveClientMember(
        [Required] OctoObjectId rtId,
        [Required] string clientId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupRemoveMemberMethodId, rtId.ToString(),
            new GroupRemoveMemberParameters { MemberKind = RtGroupMemberKindEnum.Client, MemberId = clientId }, User,
            HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions()
            .MapError(GroupMethodErrors.MemberNotInGroup, _ => Ok())
            // an rtId that names no client and no member: nothing to remove, as before; anything else names no client
            .MapError(GroupMethodErrors.MemberNotFound,
                error => OctoObjectId.TryParse(clientId.Trim(), out _) ? Ok() : ClientNotFound(clientId)));
    }

    private NotFoundObjectResult ClientNotFound(string clientId) =>
        NotFound(new NotFoundErrorDto(
            $"Client '{clientId}' not found. Name the client by its client id or by its rtId."));

    private NotFoundObjectResult UserNotFound(string userId) =>
        NotFound(new NotFoundErrorDto($"User '{userId}' not found."));

    // ========================================
    // Nested group members
    // ========================================

    /// <summary>
    /// Gets the nested group member IDs of a group.
    /// </summary>
    [HttpGet("{rtId}/members/groups")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Gets the nested group member IDs of a group.")]
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<List<string>>> GetGroupMembers([Required] OctoObjectId rtId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        var memberGroupIds = await groupStore.GetMemberGroupIdsAsync(rtId);
        return Ok(memberGroupIds.ToList());
    }

    /// <summary>
    /// Adds a nested group to a group. Rejects if it would create a cycle. Facade of the CK method
    /// <c>Group.AddChildGroup-1</c>.
    /// </summary>
    /// <remarks>
    /// A group in itself and a cycle are <c>400</c> with the earlier messages (<c>GROUP_CYCLE</c>); a child group that is
    /// already a member is <c>200</c> without a change.
    /// </remarks>
    [HttpPut("{rtId}/members/groups/{childGroupId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Adds a nested group. Rejects if it would create a circular reference.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddGroupMember(
        [Required] OctoObjectId rtId,
        [Required] string childGroupId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupAddChildGroupMethodId, rtId.ToString(),
            new GroupAddChildGroupParameters { ChildGroupId = childGroupId }, User, HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions()
            .MapError(GroupChildGroupErrors.ChildGroupNotFound, _ => NotFound(ChildGroupNotFoundMessage))
            .MapError(GroupChildGroupErrors.ChildGroupAlreadyInGroup, _ => Ok())
            .MapError(GroupChildGroupErrors.GroupCycle, error =>
                BadRequest(error.Parameters.GetValueOrDefault(GroupChildGroupErrors.CycleKindParameter) ==
                           GroupChildGroupErrors.CycleSelf
                    ? "A group cannot be a member of itself."
                    : "Adding this group would create a circular reference.")));
    }

    /// <summary>
    /// Removes a nested group from a group. Facade of the CK method <c>Group.RemoveChildGroup-1</c>.
    /// </summary>
    /// <remarks>A child group that is not a member is <c>200</c> without a change, as before.</remarks>
    [HttpDelete("{rtId}/members/groups/{childGroupId}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Removes a nested group from a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveGroupMember(
        [Required] OctoObjectId rtId,
        [Required] string childGroupId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.GroupCkTypeId,
            SystemIdentityCkIds.GroupRemoveChildGroupMethodId, rtId.ToString(),
            new GroupRemoveChildGroupParameters { ChildGroupId = childGroupId }, User, HttpContext.RequestAborted);
        return await ToFacadeResultAsync(response, rtId, new CkMethodFacadeOptions()
            .MapError(GroupChildGroupErrors.ChildGroupNotFound, _ => NotFound(ChildGroupNotFoundMessage))
            .MapError(GroupChildGroupErrors.ChildGroupNotInGroup, _ => Ok()));
    }

    private const string ChildGroupNotFoundMessage = "Child group not found.";

    /// <summary>
    /// The REST answer of a group method: <c>200</c> on success, the audited 403/409 problem answer of the role change guard
    /// (WARN log and <c>Identity.RoleChangeRefused</c> record) for a guard refusal, a missing group as an empty
    /// <c>404</c>, the endpoint's own mappings, else the facade defaults (an unexpected failure is <c>500</c>
    /// <c>METHOD_HANDLER_FAILED</c> without exception text).
    /// </summary>
    private async Task<IActionResult> ToFacadeResultAsync(CkMethodResponse response, OctoObjectId groupRtId,
        CkMethodFacadeOptions options)
    {
        if (RoleChangeProblems.RefusalOf(response) is { } decision)
        {
            return await roleChangeRefusals.RefuseAsync(HttpContext, RoleChangeCaller.FromPrincipal(User), decision,
                $"group {groupRtId}");
        }

        return response.ToActionResult(options
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => NotFound()));
    }

    /// <summary>The role id of a <c>ROLE_NOT_FOUND</c> answer of <c>Group.SetRoles</c> (the method names the role).</summary>
    private static string RoleIdOf(CkMethodError error, IReadOnlyDictionary<string, string> roleIdsByName) =>
        error.Parameters.TryGetValue(UserRoleMethodErrors.RoleNameParameter, out var name) &&
        roleIdsByName.TryGetValue(name, out var id)
            ? id
            : name ?? string.Empty;

    private async Task<GroupDto> MapToDtoAsync(RtGroup group)
    {
        var roleIds = await groupStore.GetRoleIdsAsync(group.RtId);
        var memberUserIds = await groupStore.GetMemberUserIdsAsync(group.RtId);
        var memberExternalUserIds = await groupStore.GetMemberExternalUserIdsAsync(group.RtId);
        var memberClientIds = await groupStore.GetMemberClientIdsAsync(group.RtId);
        var memberGroupIds = await groupStore.GetMemberGroupIdsAsync(group.RtId);

        return new GroupDto
        {
            Id = group.RtId,
            GroupName = group.GroupName ?? string.Empty,
            GroupDescription = group.GroupDescription,
            RoleIds = roleIds.ToList(),
            MemberUserIds = memberUserIds.ToList(),
            MemberExternalUserIds = memberExternalUserIds.ToList(),
            MemberClientIds = memberClientIds.ToList(),
            MemberGroupIds = memberGroupIds.ToList()
        };
    }
}

