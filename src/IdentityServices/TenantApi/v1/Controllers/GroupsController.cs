using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// REST Controller for managing groups with role assignments.
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class GroupsController(IGroupStore groupStore) : ControllerBase
{
    /// <summary>
    /// Returns all groups.
    /// </summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    /// Creates a new group.
    /// </summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new group.")]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<GroupDto>> Create(
        [Required][FromBody][Description("The group data")] CreateGroupDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var existing = await groupStore.FindByNameAsync(dto.GroupName.ToUpperInvariant());
        if (existing != null)
        {
            return Conflict($"A group with name '{dto.GroupName}' already exists.");
        }

        var group = new RtGroup
        {
            RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
            GroupName = dto.GroupName,
            NormalizedGroupName = dto.GroupName.ToUpperInvariant(),
            GroupDescription = dto.GroupDescription
        };

        await groupStore.StoreAsync(group);

        // Set initial role assignments via associations
        if (dto.RoleIds is { Count: > 0 })
        {
            await groupStore.SetRoleIdsAsync(group.RtId, dto.RoleIds);
        }

        return CreatedAtAction(
            nameof(GetById),
            new { rtId = group.RtId },
            await MapToDtoAsync(group));
    }

    /// <summary>
    /// Updates an existing group's name and description.
    /// </summary>
    [HttpPut("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates an existing group.")]
    [ProducesResponseType(typeof(GroupDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<ActionResult<GroupDto>> Update(
        [Required] OctoObjectId rtId,
        [Required][FromBody][Description("The updated group data")] UpdateGroupDto dto)
    {
        var existing = await groupStore.FindByIdAsync(rtId);
        if (existing == null)
        {
            return NotFound();
        }

        // Check for name conflict if name changed
        var newNormalized = dto.GroupName.ToUpperInvariant();
        if (newNormalized != existing.NormalizedGroupName)
        {
            var conflict = await groupStore.FindByNameAsync(newNormalized);
            if (conflict != null)
            {
                return Conflict($"A group with name '{dto.GroupName}' already exists.");
            }
        }

        existing.GroupName = dto.GroupName;
        existing.NormalizedGroupName = newNormalized;
        existing.GroupDescription = dto.GroupDescription;

        await groupStore.StoreAsync(existing);

        return Ok(await MapToDtoAsync(existing));
    }

    /// <summary>
    /// Deletes a group.
    /// </summary>
    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete([Required] OctoObjectId rtId)
    {
        var existing = await groupStore.FindByIdAsync(rtId);
        if (existing == null)
        {
            return NotFound();
        }

        await groupStore.RemoveAsync(rtId);
        return Ok();
    }

    // ========================================
    // Role assignments
    // ========================================

    /// <summary>
    /// Gets the role IDs assigned to a group.
    /// </summary>
    [HttpGet("{rtId}/roles")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    /// Replaces the role assignments for a group.
    /// </summary>
    [HttpPut("{rtId}/roles")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Replaces the role assignments for a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateRoles(
        [Required] OctoObjectId rtId,
        [Required][FromBody] List<string> roleIds)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        await groupStore.SetRoleIdsAsync(rtId, roleIds);
        return Ok();
    }

    // ========================================
    // User members
    // ========================================

    /// <summary>
    /// Gets the user member IDs of a group.
    /// </summary>
    [HttpGet("{rtId}/members/users")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    /// Adds a user to a group.
    /// </summary>
    [HttpPut("{rtId}/members/users/{userId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Adds a user to a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddUserMember(
        [Required] OctoObjectId rtId,
        [Required] string userId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        await groupStore.AddMemberUserAsync(rtId, userId);
        return Ok();
    }

    /// <summary>
    /// Removes a user from a group.
    /// </summary>
    [HttpDelete("{rtId}/members/users/{userId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Removes a user from a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveUserMember(
        [Required] OctoObjectId rtId,
        [Required] string userId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        await groupStore.RemoveMemberUserAsync(rtId, userId);
        return Ok();
    }

    // ========================================
    // Nested group members
    // ========================================

    /// <summary>
    /// Gets the nested group member IDs of a group.
    /// </summary>
    [HttpGet("{rtId}/members/groups")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    /// Adds a nested group to a group. Rejects if it would create a cycle.
    /// </summary>
    [HttpPut("{rtId}/members/groups/{childGroupId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Adds a nested group. Rejects if it would create a circular reference.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddGroupMember(
        [Required] OctoObjectId rtId,
        [Required] string childGroupId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        var childGroup = await groupStore.FindByIdAsync(new OctoObjectId(childGroupId));
        if (childGroup == null)
        {
            return NotFound("Child group not found.");
        }

        // Prevent self-reference
        if (rtId == childGroup.RtId)
        {
            return BadRequest("A group cannot be a member of itself.");
        }

        // Circular reference check: verify that the parent (rtId) is not reachable
        // from the child group via ChildGroup associations
        if (await WouldCreateCycleAsync(rtId, childGroup.RtId))
        {
            return BadRequest("Adding this group would create a circular reference.");
        }

        await groupStore.AddMemberGroupAsync(rtId, childGroupId);
        return Ok();
    }

    /// <summary>
    /// Removes a nested group from a group.
    /// </summary>
    [HttpDelete("{rtId}/members/groups/{childGroupId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Removes a nested group from a group.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveGroupMember(
        [Required] OctoObjectId rtId,
        [Required] string childGroupId)
    {
        var group = await groupStore.FindByIdAsync(rtId);
        if (group == null)
        {
            return NotFound();
        }

        await groupStore.RemoveMemberGroupAsync(rtId, childGroupId);
        return Ok();
    }

    /// <summary>
    /// Checks if adding childGroupId as a member of parentId would create a cycle.
    /// Uses DFS via ChildGroup associations from the child to see if the parent is reachable.
    /// </summary>
    private async Task<bool> WouldCreateCycleAsync(OctoObjectId parentId, OctoObjectId childGroupId)
    {
        var visited = new HashSet<string>();
        var stack = new Stack<string>();

        // Start from the child's nested groups
        var childGroupMemberIds = await groupStore.GetMemberGroupIdsAsync(childGroupId);
        foreach (var id in childGroupMemberIds)
        {
            stack.Push(id);
        }

        var parentIdString = parentId.ToString();

        while (stack.Count > 0)
        {
            var currentId = stack.Pop();

            if (currentId == parentIdString)
            {
                return true;
            }

            if (!visited.Add(currentId))
            {
                continue;
            }

            var nestedGroupIds = await groupStore.GetMemberGroupIdsAsync(new OctoObjectId(currentId));
            foreach (var nestedId in nestedGroupIds)
            {
                stack.Push(nestedId);
            }
        }

        return false;
    }

    private async Task<GroupDto> MapToDtoAsync(RtGroup group)
    {
        var roleIds = await groupStore.GetRoleIdsAsync(group.RtId);
        var memberUserIds = await groupStore.GetMemberUserIdsAsync(group.RtId);
        var memberExternalUserIds = await groupStore.GetMemberExternalUserIdsAsync(group.RtId);
        var memberGroupIds = await groupStore.GetMemberGroupIdsAsync(group.RtId);

        return new GroupDto
        {
            Id = group.RtId,
            GroupName = group.GroupName ?? string.Empty,
            GroupDescription = group.GroupDescription,
            RoleIds = roleIds.ToList(),
            MemberUserIds = memberUserIds.ToList(),
            MemberExternalUserIds = memberExternalUserIds.ToList(),
            MemberGroupIds = memberGroupIds.ToList()
        };
    }
}

public record GroupDto
{
    public OctoObjectId? Id { get; init; }
    public string GroupName { get; init; } = string.Empty;
    public string? GroupDescription { get; init; }
    public List<string> RoleIds { get; init; } = [];
    public List<string> MemberUserIds { get; init; } = [];
    public List<string> MemberExternalUserIds { get; init; } = [];
    public List<string> MemberGroupIds { get; init; } = [];
}

public record CreateGroupDto
{
    [Required]
    public string GroupName { get; init; } = string.Empty;

    public string? GroupDescription { get; init; }

    public List<string>? RoleIds { get; init; }
}

public record UpdateGroupDto
{
    [Required]
    public string GroupName { get; init; } = string.Empty;

    public string? GroupDescription { get; init; }
}
