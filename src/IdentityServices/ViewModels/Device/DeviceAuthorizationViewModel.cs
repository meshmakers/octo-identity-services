using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Consent;

#pragma warning disable 1591

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Device;

public class DeviceAuthorizationViewModel : ConsentViewModel
{
    public string? UserCode { get; set; }
    public bool ConfirmUserCode { get; set; }
}
