using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
/// Store for managing role assignments of a <c>Client</c> (machine-to-machine identity) via CK
/// <c>AssignedRole</c> associations — the same association used for users and groups. Mirrors the
/// user-side role machinery in <see cref="OctoUserStore" /> so that a client_credentials token can
/// carry the same role claims as a user token.
/// </summary>
public interface IClientRoleStore
{
    /// <summary>
    /// Gets the RtIds of the roles directly assigned to the client (via <c>AssignedRole</c>),
    /// excluding roles inherited from groups.
    /// </summary>
    Task<IReadOnlyList<string>> GetDirectRoleIdsAsync(OctoObjectId clientRtId);

    /// <summary>
    /// Replaces the directly-assigned roles of a client with the given role RtIds. Diffs current vs
    /// desired and creates/deletes <c>AssignedRole</c> associations accordingly (replace-all).
    /// </summary>
    Task SetRoleIdsAsync(OctoObjectId clientRtId, IReadOnlyList<string> roleIds);

    /// <summary>
    /// Adds a single role (by role name) to the client. No-op if already assigned.
    /// </summary>
    Task AddRoleAsync(OctoObjectId clientRtId, string roleName);

    /// <summary>
    /// Removes a single role (by role name) from the client. No-op if not assigned or unknown role.
    /// </summary>
    Task RemoveRoleAsync(OctoObjectId clientRtId, string roleName);

    /// <summary>
    /// Resolves the effective role <b>names</b> for the client: the directly-assigned roles merged
    /// with all roles inherited from group memberships (incl. nested groups). This is the set that
    /// is emitted as <c>role</c> claims into the client_credentials access token, in the same shape
    /// as user tokens.
    /// </summary>
    Task<IReadOnlySet<string>> GetEffectiveRoleNamesAsync(OctoObjectId clientRtId);
}
