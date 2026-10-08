using System.Globalization;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Resources;
using Xunit;

namespace IdentityServices.UnitTests.Resources;

/// <summary>
///     The password-policy descriptions are returned to callers as identity error descriptions
///     and shown in the UI. CK v2 defect D7 (AB#5902): the German
///     <c>PasswordRequiresDigit</c> text was truncated ("wörter müssen ...").
/// </summary>
public class PasswordPolicyTextsTests
{
    public static TheoryData<string> PolicyKeys =>
    [
        "Backend_Persistence_Identity_PasswordRequiresDigit",
        "Backend_Persistence_Identity_PasswordRequiresUniqueChars",
        "Backend_Persistence_Identity_PasswordRequiresUpper",
        "Backend_Persistence_Identity_PasswordRequiresNonAlphanumeric",
        "Backend_Persistence_Identity_PasswordRequiresLower",
        "Backend_Persistence_Identity_PasswordTooShort"
    ];

    [Theory]
    [MemberData(nameof(PolicyKeys))]
    public void GermanPolicyTexts_StartWithPasswoerter(string key)
    {
        var text = IdentityTexts.ResourceManager.GetString(key, CultureInfo.GetCultureInfo("de"));

        text.Should().StartWith("Passwörter müssen mindestens ");
    }

    [Theory]
    [MemberData(nameof(PolicyKeys))]
    public void EnglishPolicyTexts_StartWithPasswords(string key)
    {
        var text = IdentityTexts.ResourceManager.GetString(key, CultureInfo.InvariantCulture);

        text.Should().StartWith("Passwords must");
    }
}
