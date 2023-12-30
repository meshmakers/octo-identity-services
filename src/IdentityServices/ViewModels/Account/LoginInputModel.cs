using System.ComponentModel.DataAnnotations;
using Meshmakers.Octo.Backend.IdentityServices.Resources;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Account;

public class LoginInputModel
{
    [Required(ErrorMessageResourceName = nameof(IdentityTexts.Backend_Identity_LogIn_Validation_Username),
        ErrorMessageResourceType = typeof(IdentityTexts))]
    [Display(ResourceType = typeof(IdentityTexts), Name = nameof(IdentityTexts.Backend_Identity_General_Username_Label))]
    public string? Username { get; set; }

    [Required(ErrorMessageResourceName = nameof(IdentityTexts.Backend_Identity_LogIn_Validation_Password),
        ErrorMessageResourceType = typeof(IdentityTexts))]
    [Display(ResourceType = typeof(IdentityTexts), Name = nameof(IdentityTexts.Backend_Identity_General_Password_Label))]
    public string? Password { get; set; }

    public bool RememberLogin { get; set; }

    public string? ReturnUrl { get; set; }
}