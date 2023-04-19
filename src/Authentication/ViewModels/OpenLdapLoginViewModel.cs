using System.ComponentModel.DataAnnotations;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.Authentication.ViewModels;

public class OpenLdapLoginViewModel
{
    [Required(ErrorMessageResourceName = nameof(IdentityTexts.Backend_Identity_LogIn_Validation_Username),
        ErrorMessageResourceType = typeof(IdentityTexts))]
    [Display(ResourceType = typeof(IdentityTexts), Name = nameof(IdentityTexts.Backend_Identity_General_Username_Label))]
    public string UserName { get; set; } = null!;
    [Required(ErrorMessageResourceName = nameof(IdentityTexts.Backend_Identity_LogIn_Validation_Password), ErrorMessageResourceType = typeof(IdentityTexts))]
    [Display(ResourceType = typeof(IdentityTexts), Name = nameof(IdentityTexts.Backend_Identity_General_Password_Label))]
    public string Password { get; set; } = null!;

    public string LoginProvider { get; set; } = null!;
    public bool RememberLogin { get; set; }
    [HiddenInput]
    public string? XsrfId { get; set; }

    [HiddenInput] public string ReturnUrl { get; set; } = null!;
}
