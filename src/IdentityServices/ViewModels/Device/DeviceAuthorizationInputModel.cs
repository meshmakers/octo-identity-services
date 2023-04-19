using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Consent;

#pragma warning disable 1591

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Device;

public class DeviceAuthorizationInputModel : ConsentInputModel
{
    public string? UserCode { get; set; }
}
