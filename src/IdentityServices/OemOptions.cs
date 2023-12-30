#pragma warning disable 1591
namespace Meshmakers.Octo.Backend.IdentityServices;

public class OemOptions
{
    public OemOptions()
    {
        ApplicationName = "Octo Mesh Identity Services";
        HideNavigation = false;
    }

    public string ApplicationName { get; set; }
    public bool HideNavigation { get; set; }
    public string? DefaultLanguage { get; set; }
}