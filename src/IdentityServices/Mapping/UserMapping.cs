using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Mapping;

public static class UserMapping
{
    public static UserDto ToDto(this RtUser user) => new()
    {
        UserId = user.RtId.ToString(),
        Name = user.UserName,
        FirstName = user.FirstName,
        LastName = user.LastName,
        Email = user.Email,
        ResetPasswordOnLogin = user.ResetPasswordOnLogin,
        ExternalLogins = ToExternalLoginDtos(user)
    };

    public static RtUser ToEntity(this UserDto dto)
    {
        var user = new RtUser();
        dto.ApplyTo(user);
        return user;
    }

    public static void ApplyTo(this UserDto dto, RtUser user)
    {
        user.UserName = dto.Name;
        user.FirstName = dto.FirstName;
        user.LastName = dto.LastName;
        user.Email = dto.Email;
        user.ResetPasswordOnLogin = dto.ResetPasswordOnLogin;
    }

    private static List<ExternalLoginDto> ToExternalLoginDtos(RtUser user)
    {
        if (user.UserLogins == null)
        {
            return [];
        }

        return user.UserLogins.Select(ToExternalLoginDto).ToList();
    }

    private static ExternalLoginDto ToExternalLoginDto(RtUserLoginRecord login) => new()
    {
        LoginProvider = login.LoginProvider,
        ProviderDisplayName = login.ProviderDisplayName ?? login.LoginProvider,
        ProviderKey = login.ProviderKey
    };
}
