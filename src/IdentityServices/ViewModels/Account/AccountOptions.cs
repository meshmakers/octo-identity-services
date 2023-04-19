#pragma warning disable 1591

using System;
using Meshmakers.Octo.Backend.IdentityServices.Resources;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Account;

public static class AccountOptions
{
    public static readonly bool AllowLocalLogin = true;
    public static readonly bool AllowRememberLogin = true;
    public static readonly TimeSpan RememberMeLoginDuration = TimeSpan.FromDays(30);

    public static readonly bool ShowLogoutPrompt = true;
    public static readonly bool AutomaticRedirectAfterSignOut = true;

    // if user uses windows auth, should we load the groups from windows
    public static readonly bool IncludeWindowsGroups = false;

    public static readonly string InvalidCredentialsErrorMessage = IdentityTexts.Backend_Identity_Login_InvalidUserPassword;
}
