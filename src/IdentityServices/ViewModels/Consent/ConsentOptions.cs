namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Consent;

// ReSharper disable once ClassNeverInstantiated.Global
public class ConsentOptions
{
    public static readonly string MustChooseOneErrorMessage = "You must pick at least one permission";

    public static readonly string InvalidSelectionErrorMessage = "Invalid selection";

    public static bool EnableOfflineAccess { get; set; } = true;

    public static string OfflineAccessDisplayName { get; set; } = "Offline Access";

    public static string OfflineAccessDescription { get; set; } =
        "Access to your applications and resources, even when you are offline";
}
