using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
/// Store for managing groups with role assignments via CK associations.
/// Groups can contain users, external user mappings, and nested child groups.
/// </summary>
public interface IGroupStore
{
    /// <summary>
    /// Finds a group by its RtId.
    /// </summary>
    Task<RtGroup?> FindByIdAsync(OctoObjectId rtId);

    /// <summary>
    /// Finds a group by its normalized name.
    /// </summary>
    Task<RtGroup?> FindByNameAsync(string normalizedGroupName);

    /// <summary>
    /// Gets all groups for the current tenant with optional pagination.
    /// </summary>
    Task<IEnumerable<RtGroup>> GetAllAsync(int? skip = null, int? take = null);

    /// <summary>
    /// Stores (creates or updates) a group entity (name, description only).
    /// </summary>
    Task StoreAsync(RtGroup group);

    /// <summary>
    /// Removes a group and all its associations by its RtId.
    /// </summary>
    Task RemoveAsync(OctoObjectId rtId);

    // ========================================
    // Role associations (AssignedRole)
    // ========================================

    /// <summary>
    /// Gets the role RtIds assigned to a group via AssignedRole associations.
    /// </summary>
    Task<IReadOnlyList<string>> GetRoleIdsAsync(OctoObjectId groupRtId);

    /// <summary>
    /// Replaces the role assignments for a group. Diffs current vs desired and creates/deletes associations.
    /// </summary>
    Task SetRoleIdsAsync(OctoObjectId groupRtId, IReadOnlyList<string> roleIds);

    // ========================================
    // User member associations (GroupMember → User)
    // ========================================

    /// <summary>
    /// Gets the user member RtIds of a group via GroupMember associations.
    /// </summary>
    Task<IReadOnlyList<string>> GetMemberUserIdsAsync(OctoObjectId groupRtId);

    /// <summary>
    /// Adds a user as a member of a group via GroupMember association.
    /// </summary>
    Task AddMemberUserAsync(OctoObjectId groupRtId, string userId);

    /// <summary>
    /// Removes a user from a group via GroupMember association.
    /// </summary>
    Task RemoveMemberUserAsync(OctoObjectId groupRtId, string userId);

    // ========================================
    // External user member associations (GroupMember → ExternalTenantUserMapping)
    // ========================================

    /// <summary>
    /// Gets the external user member RtIds of a group via GroupMember associations.
    /// </summary>
    Task<IReadOnlyList<string>> GetMemberExternalUserIdsAsync(OctoObjectId groupRtId);

    // ========================================
    // Client member associations (GroupMember → Client)
    // ========================================

    /// <summary>
    /// Gets the client member RtIds of a group via GroupMember associations.
    /// </summary>
    Task<IReadOnlyList<string>> GetMemberClientIdsAsync(OctoObjectId groupRtId);

    /// <summary>
    /// Adds a client as a member of a group via GroupMember association.
    /// </summary>
    Task AddMemberClientAsync(OctoObjectId groupRtId, string clientId);

    /// <summary>
    /// Removes a client from a group via GroupMember association.
    /// </summary>
    Task RemoveMemberClientAsync(OctoObjectId groupRtId, string clientId);

    /// <summary>
    /// Gets the RtIds of <b>all</b> direct member subjects of a group (users, clients and external
    /// user mappings) via GroupMember associations, regardless of the member's CK type. Used by the
    /// role resolver to determine group membership for any subject (user or client).
    /// </summary>
    Task<IReadOnlyList<string>> GetAllMemberSubjectIdsAsync(OctoObjectId groupRtId);

    // ========================================
    // Child group associations (ChildGroup)
    // ========================================

    /// <summary>
    /// Gets the child group RtIds of a group via ChildGroup associations.
    /// </summary>
    Task<IReadOnlyList<string>> GetMemberGroupIdsAsync(OctoObjectId groupRtId);

    /// <summary>
    /// Adds a child group to a parent group via ChildGroup association.
    /// </summary>
    Task AddMemberGroupAsync(OctoObjectId groupRtId, string childGroupId);

    /// <summary>
    /// Removes a child group from a parent group via ChildGroup association.
    /// </summary>
    Task RemoveMemberGroupAsync(OctoObjectId groupRtId, string childGroupId);
}
