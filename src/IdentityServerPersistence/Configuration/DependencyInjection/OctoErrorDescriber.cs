using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerPersistence.Configuration.DependencyInjection;

// ReSharper disable once ClassNeverInstantiated.Global
internal class OctoErrorDescriber : IdentityErrorDescriber
{
    public override IdentityError DuplicateEmail(string email)
    {
        return new IdentityError
        {
            Code = nameof(DuplicateEmail),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_DuplicateEmail, email)
        };
    }

    public override IdentityError DuplicateUserName(string userName)
    {
        return new IdentityError
        {
            Code = nameof(DuplicateUserName),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_DuplicateUserName, userName)
        };
    }

    public override IdentityError InvalidEmail(string? email)
    {
        return new IdentityError
        {
            Code = nameof(InvalidEmail),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_InvalidEmail, email)
        };
    }

    public override IdentityError DuplicateRoleName(string role)
    {
        return new IdentityError
        {
            Code = nameof(DuplicateRoleName),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_DuplicateRoleName, role)
        };
    }

    public override IdentityError InvalidRoleName(string? role)
    {
        return new IdentityError
        {
            Code = nameof(InvalidRoleName),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_InvalidRoleName, role)
        };
    }

    public override IdentityError InvalidToken()
    {
        return new IdentityError
        {
            Code = nameof(InvalidToken),
            Description = IdentityTexts.Backend_Persistence_Identity_InvalidToken
        };
    }

    public override IdentityError InvalidUserName(string? userName)
    {
        return new IdentityError
        {
            Code = nameof(InvalidUserName),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_InvalidUserName, userName)
        };
    }

    public override IdentityError LoginAlreadyAssociated()
    {
        return new IdentityError
        {
            Code = nameof(LoginAlreadyAssociated),
            Description = IdentityTexts.Backend_Persistence_Identity_LoginAlreadyAssociated
        };
    }

    public override IdentityError PasswordMismatch()
    {
        return new IdentityError
        {
            Code = nameof(PasswordMismatch),
            Description = IdentityTexts.Backend_Persistence_Identity_PasswordMismatch
        };
    }

    public override IdentityError PasswordRequiresDigit()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresDigit),
            Description = IdentityTexts.Backend_Persistence_Identity_PasswordRequiresDigit
        };
    }

    public override IdentityError PasswordRequiresLower()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresLower),
            Description = IdentityTexts.Backend_Persistence_Identity_PasswordRequiresLower
        };
    }

    public override IdentityError PasswordRequiresNonAlphanumeric()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresNonAlphanumeric),
            Description = IdentityTexts.Backend_Persistence_Identity_PasswordRequiresNonAlphanumeric
        };
    }

    public override IdentityError PasswordRequiresUniqueChars(int uniqueChars)
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresUniqueChars),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_PasswordRequiresUniqueChars, uniqueChars)
        };
    }

    public override IdentityError PasswordRequiresUpper()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresUpper),
            Description = IdentityTexts.Backend_Persistence_Identity_PasswordRequiresUpper
        };
    }

    public override IdentityError PasswordTooShort(int length)
    {
        return new IdentityError
        {
            Code = nameof(PasswordTooShort),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_PasswordTooShort, length)
        };
    }

    public override IdentityError UserAlreadyHasPassword()
    {
        return new IdentityError
        {
            Code = nameof(UserAlreadyHasPassword),
            Description = IdentityTexts.Backend_Persistence_Identity_UserAlreadyHasPassword
        };
    }

    public override IdentityError UserAlreadyInRole(string role)
    {
        return new IdentityError
        {
            Code = nameof(UserAlreadyInRole),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_UserAlreadyInRole, role)
        };
    }

    public override IdentityError UserNotInRole(string role)
    {
        return new IdentityError
        {
            Code = nameof(UserNotInRole),
            Description = string.Format(IdentityTexts.Backend_Persistence_Identity_UserNotInRole, role)
        };
    }

    public override IdentityError UserLockoutNotEnabled()
    {
        return new IdentityError
        {
            Code = nameof(UserLockoutNotEnabled),
            Description = IdentityTexts.Backend_Persistence_Identity_UserLockoutNotEnabled
        };
    }

    public override IdentityError RecoveryCodeRedemptionFailed()
    {
        return new IdentityError
        {
            Code = nameof(RecoveryCodeRedemptionFailed),
            Description = IdentityTexts.Backend_Persistence_Identity_RecoveryCodeRedemptionFailed
        };
    }

    public override IdentityError ConcurrencyFailure()
    {
        return new IdentityError
        {
            Code = nameof(ConcurrencyFailure),
            Description = IdentityTexts.Backend_Persistence_Identity_ConcurrencyFailure
        };
    }

    public override IdentityError DefaultError()
    {
        return new IdentityError
        {
            Code = nameof(DefaultError),
            Description = IdentityTexts.Backend_Persistence_Identity_DefaultIdentityError
        };
    }
}