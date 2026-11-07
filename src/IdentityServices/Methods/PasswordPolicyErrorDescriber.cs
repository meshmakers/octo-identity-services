using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Rebuilds the <see cref="IdentityError" /> list of a <c>PASSWORD_POLICY_VIOLATION</c> envelope for a REST facade. The
///     envelope carries the codes of the failed rules only (never a value, never a text); the descriptions come from the
///     error describer and the password options of this service, so a REST body keeps the text it had before the facade.
/// </summary>
internal static class PasswordPolicyErrorDescriber
{
    /// <summary>One <see cref="IdentityError" /> per detail code of <paramref name="error" />, in the order of the envelope.</summary>
    public static IReadOnlyList<IdentityError> Describe(UserManager<RtUser> userManager, CkMethodError error)
    {
        var describer = userManager.ErrorDescriber;
        var password = userManager.Options.Password;
        return (error.Details ?? []).Select(d => d.Code).Where(c => !string.IsNullOrWhiteSpace(c)).Select(code =>
            code switch
            {
                nameof(IdentityErrorDescriber.PasswordTooShort) => describer.PasswordTooShort(password.RequiredLength),
                nameof(IdentityErrorDescriber.PasswordRequiresUniqueChars) =>
                    describer.PasswordRequiresUniqueChars(password.RequiredUniqueChars),
                nameof(IdentityErrorDescriber.PasswordRequiresNonAlphanumeric) =>
                    describer.PasswordRequiresNonAlphanumeric(),
                nameof(IdentityErrorDescriber.PasswordRequiresDigit) => describer.PasswordRequiresDigit(),
                nameof(IdentityErrorDescriber.PasswordRequiresLower) => describer.PasswordRequiresLower(),
                nameof(IdentityErrorDescriber.PasswordRequiresUpper) => describer.PasswordRequiresUpper(),
                _ => new IdentityError { Code = code!, Description = code! }
            }).ToList();
    }
}
