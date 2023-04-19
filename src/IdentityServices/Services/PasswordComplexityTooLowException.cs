using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class PasswordComplexityTooLowException : UserEmailInteractionException
{
    public PasswordComplexityTooLowException(string message) : base(message)
    {
    }

    public PasswordComplexityTooLowException(string message, IEnumerable<IdentityError> errors) : base(message, errors)
    {
    }
    
    public static PasswordComplexityTooLowException PasswordChangeFailed(string reason, IEnumerable<IdentityError> errors) => new($"Password change failed: {reason}", errors);

}
