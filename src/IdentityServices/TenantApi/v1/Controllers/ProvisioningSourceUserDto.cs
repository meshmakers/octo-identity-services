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
