using System.ComponentModel.DataAnnotations;
using Meshmakers.Octo.Backend.IdentityServices.Resources;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Manage;

public class ResetPasswordViewModel : IValidatableObject
{
    public string? Token { get; set; }
    public string? NewPassword { get; set; }
    public string? ConfirmPassword { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (NewPassword is null || ConfirmPassword is null)
            yield return new ValidationResult(IdentityTexts.Backend_Identity_ConfirmNewPassword_PasswordRequired,
                new[] { nameof(NewPassword) });
        if (NewPassword != ConfirmPassword)
            yield return new ValidationResult(IdentityTexts.Backend_Identity_ConfirmNewPassword_PasswordMismatch,
                new[] { nameof(NewPassword) });
    }
}