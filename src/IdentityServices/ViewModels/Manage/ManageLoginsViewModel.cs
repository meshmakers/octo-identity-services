using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

#pragma warning disable 1591

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Manage;

public class ManageLoginsViewModel
{
    public IList<UserLoginInfo>? CurrentLogins { get; set; }

    public IList<AuthenticationScheme>? OtherLogins { get; set; }
}