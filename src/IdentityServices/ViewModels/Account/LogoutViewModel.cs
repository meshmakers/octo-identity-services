namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Account;

public class LogoutViewModel : LogoutInputModel
{
    public bool ShowLogoutPrompt { get; set; } = true;
}