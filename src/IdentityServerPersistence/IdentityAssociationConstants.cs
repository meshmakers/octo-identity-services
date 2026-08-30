using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence;

public static class IdentityAssociationConstants
{
    public static readonly RtCkId<CkAssociationRoleId> AssignedRoleId = new("System.Identity/AssignedRole");
    public static readonly RtCkId<CkAssociationRoleId> GroupMemberId = new("System.Identity/GroupMember");
    public static readonly RtCkId<CkAssociationRoleId> ChildGroupId = new("System.Identity/ChildGroup");
    public static readonly RtCkId<CkAssociationRoleId> GrantsPermissionId = new("System.Identity/GrantsPermission");
    public static readonly RtCkId<CkAssociationRoleId> PolicyPermissionId = new("System.Identity/PolicyPermission");
}
