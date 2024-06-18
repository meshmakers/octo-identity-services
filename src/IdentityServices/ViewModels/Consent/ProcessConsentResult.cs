using Duende.IdentityServer.Models;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Consent;

public class ProcessConsentResult
{
    public bool IsRedirect => RedirectUri != null;
    public string? RedirectUri { get; set; }

    // ReSharper disable once UnusedAutoPropertyAccessor.Global
    public Client? Client { get; set; }

    public bool ShowView => ViewModel != null;
    public ConsentViewModel? ViewModel { get; set; }

    public bool HasValidationError => ValidationError != null;
    public string? ValidationError { get; set; }
}