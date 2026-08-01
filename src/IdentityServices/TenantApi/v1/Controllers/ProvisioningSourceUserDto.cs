namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// A candidate user from an ancestor (parent) tenant that can be provisioned as a cross-tenant
/// user in a target tenant. Returned by the admin-provisioning source-user search so the Studio
/// can offer a picker without exposing the parent tenant's full user directory.
/// </summary>
public sealed class ProvisioningSourceUserDto
{
    /// <summary>The ancestor tenant the user lives in (becomes the mapping's SourceTenantId).</summary>
    public required string SourceTenantId { get; init; }

    /// <summary>The user's RtId in the source tenant (becomes the mapping's SourceUserId).</summary>
    public required string UserId { get; init; }

    /// <summary>The user's login name (becomes the mapping's SourceUserName).</summary>
    public required string UserName { get; init; }

    /// <summary>The user's email address, when available.</summary>
    public string? Email { get; init; }

    /// <summary>The user's first name, when available.</summary>
    public string? FirstName { get; init; }

    /// <summary>The user's last name, when available.</summary>
    public string? LastName { get; init; }
}

/// <summary>
/// A role defined in the target tenant, offered as an assignable option when creating a
/// cross-tenant user mapping.
/// </summary>
public sealed class ProvisioningRoleDto
{
    /// <summary>The role's RtId (goes into the mapping's RoleIds).</summary>
    public required string Id { get; init; }

    /// <summary>The role's display name.</summary>
    public required string Name { get; init; }
}

/// <summary>
/// A group defined in the target tenant, offered as an assignable option when creating a
/// cross-tenant user mapping. Assigning a group makes the mapping a GroupMember, so the user
/// inherits the group's roles — the idiomatic, group-based grant (same mechanism provisionCurrentUser
/// uses with TenantOwners).
/// </summary>
public sealed class ProvisioningGroupDto
{
    /// <summary>The group's RtId.</summary>
    public required string Id { get; init; }

    /// <summary>The group's display name.</summary>
    public required string Name { get; init; }

    /// <summary>The group's description, when set.</summary>
    public string? Description { get; init; }
}

/// <summary>
/// Request to provision a cross-tenant user mapping and make it a member of the given target-tenant
/// groups (group-based role inheritance), the counterpart of the role-based
/// <c>CreateExternalTenantUserMappingDto</c>.
/// </summary>
public sealed class CreateExternalTenantUserGroupMappingDto
{
    public required string SourceTenantId { get; init; }
    public required string SourceUserId { get; init; }
    public required string SourceUserName { get; init; }

    /// <summary>RtIds of the target-tenant groups the mapping should belong to.</summary>
    public IReadOnlyList<string>? GroupIds { get; init; }
}
