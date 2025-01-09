using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Consent;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Device;

public class DeviceAuthorizationInputModel : ConsentInputModel
{
    public string? UserCode { get; set; }
}