using System.ComponentModel.DataAnnotations;
using Meshmakers.Octo.Backend.IdentityServices.Resources;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Manage;

public class SetPasswordViewModel
{
    [Required(ErrorMessageResourceName = nameof(IdentityTexts.Backend_Identity_ChangePassword_Validation_NewPassword),
        ErrorMessageResourceType = typeof(IdentityTexts))]
    [StringLength(100, ErrorMessage = nameof(IdentityTexts.Backend_Identity_ChangePassword_Validation_NewPassword_MinMax),
        MinimumLength = 6)]
    [DataType(DataType.Password)]
    [Display(Name = nameof(IdentityTexts.Backend_Identity_NewPassword_Label), ResourceType = typeof(IdentityTexts))]

    public string? NewPassword { get; set; }

    [DataType(DataType.Password)]
    [Display(Name = nameof(IdentityTexts.Backend_Identity_ConfirmNewPassword_Label), ResourceType = typeof(IdentityTexts))]
    [Compare("NewPassword", ErrorMessageResourceName = nameof(IdentityTexts.Backend_Identity_ChangePassword_Validation_Match),
        ErrorMessageResourceType = typeof(IdentityTexts))]
    public string? ConfirmPassword { get; set; }
}
