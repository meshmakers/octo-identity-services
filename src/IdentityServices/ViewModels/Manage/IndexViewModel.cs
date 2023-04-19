using System.Collections.Generic;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Shared;
using Microsoft.AspNetCore.Identity;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Manage;

public class IndexViewModel : UserInfoViewModel
{
    public IList<UserLoginInfo>? Logins { get; set; }

    public bool BrowserRemembered { get; set; }
}
