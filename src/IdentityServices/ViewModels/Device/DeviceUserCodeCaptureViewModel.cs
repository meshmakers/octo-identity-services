using System.ComponentModel.DataAnnotations;
using Meshmakers.Octo.Backend.IdentityServices.Resources;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Device;

public class DeviceUserCodeCaptureViewModel
{
    [Required(ErrorMessageResourceName = nameof(IdentityTexts.Backend_Identity_DeviceCaptureUserCode_Validation_UserCode),
        ErrorMessageResourceType = typeof(IdentityTexts))]
    [Display(ResourceType = typeof(IdentityTexts), Name = nameof(IdentityTexts.Backend_Identity_UserCode_Header))]
    public string? UserCode { get; set; }
}