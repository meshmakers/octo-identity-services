using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Mapping;

public static class RoleMapping
{
    public static RoleDto ToDto(this RtRole role) => new()
    {
        Id = role.RtId.ToString(),
        Name = role.Name
    };

    public static RtRole ToEntity(this RoleDto dto)
    {
        var role = new RtRole();
        dto.ApplyTo(role);
        return role;
    }

    public static void ApplyTo(this RoleDto dto, RtRole role)
    {
        role.Name = dto.Name!;
    }
}
