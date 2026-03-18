using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence;

public static class IdentityAssociationConstants
{
    public static readonly RtCkId<CkAssociationRoleId> AssignedRoleId = new("System.Identity/AssignedRole");
    public static readonly RtCkId<CkAssociationRoleId> GroupMemberId = new("System.Identity/GroupMember");
    public static readonly RtCkId<CkAssociationRoleId> ChildGroupId = new("System.Identity/ChildGroup");
}
