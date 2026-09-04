using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence;

public static class IdentityAssociationConstants
{
    public static readonly RtCkId<CkAssociationRoleId> AssignedRoleId = new("System.Identity/AssignedRole");

    /// <summary>
    ///     Client → Client (AB#5114): the origin client may impersonate the target client via the
    ///     impersonation grant, and may delegate on behalf of a user through the target via the
    ///     on-behalf-of grant's <c>requested_client_id</c> extension. Materialised by the
    ///     communication reconcile for adapter→pipeline-service-account pairs.
    /// </summary>
    public static readonly RtCkId<CkAssociationRoleId> MayActAsId = new("System.Identity/MayActAs");
    public static readonly RtCkId<CkAssociationRoleId> GroupMemberId = new("System.Identity/GroupMember");
    public static readonly RtCkId<CkAssociationRoleId> ChildGroupId = new("System.Identity/ChildGroup");
    public static readonly RtCkId<CkAssociationRoleId> GrantsPermissionId = new("System.Identity/GrantsPermission");
    public static readonly RtCkId<CkAssociationRoleId> PolicyPermissionId = new("System.Identity/PolicyPermission");
}
