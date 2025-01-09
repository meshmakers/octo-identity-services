namespace Meshmakers.Octo.Backend.IdentityServices;

public class OemOptions
{
    public OemOptions()
    {
        ApplicationName = "OctoMesh";
        Copyright = "Provided by meshmakers.io";
        HideNavigation = false;
    }

    public string ApplicationName { get; set; }
    public string Copyright { get; set; }
    public bool HideNavigation { get; set; }
    public string? DefaultLanguage { get; set; }
}