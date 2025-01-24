namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

/// <summary>
///     This configuration resides in the database and is used to configure the identity server.
/// </summary>
public class EmailInteractionConfiguration
{
    public bool EnableEmailNotifications { get; set; }
    public string? RedirectAfterEmailInteractionUrl { get; set; }
}