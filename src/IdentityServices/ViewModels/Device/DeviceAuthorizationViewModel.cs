using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Consent;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Device;

public class DeviceAuthorizationViewModel : ConsentViewModel
{
    public string UserCode { get; set; } = null!;
    public bool ConfirmUserCode { get; set; }
}