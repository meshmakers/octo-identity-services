using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
/// Regression tests for external/JIT user-name generation. A provider whose free-text name
/// contained characters outside the ASP.NET Identity allowed set (e.g. spaces in
/// "Microsoft Entra ID") produced an invalid user name, so <c>UserManager.CreateAsync</c>
/// failed with InvalidUserName and the login surfaced "Failed to create user account".
/// </summary>
public class ExternalUserNameSanitizationTests
{
    [Theory]
    [InlineData("Microsoft Entra ID", "MicrosoftEntraID")]
    [InlineData("Azure AD (prod)", "AzureADprod")]
    [InlineData("AzureEntraId", "AzureEntraId")]
    [InlineData("Google", "Google")]
    [InlineData("Entra-ID", "Entra-ID")]        // safe separators are preserved
    [InlineData("my.provider_1", "my.provider_1")]
    [InlineData("  spaced  ", "spaced")]
    [InlineData("Müller", "Mller")]
    public void SanitizeUserNameComponent_StripsDisallowedCharacters(string input, string expected)
    {
        AuthApiController.SanitizeUserNameComponent(input).Should().Be(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("()!?")]
    public void SanitizeUserNameComponent_ReturnsEmpty_ForNoUsableCharacters(string? input)
    {
        AuthApiController.SanitizeUserNameComponent(input).Should().BeEmpty();
    }

    [Fact]
    public void SanitizeUserNameComponent_ResultContainsOnlyAllowedCharacters()
    {
        var result = AuthApiController.SanitizeUserNameComponent("Microsoft Entra ID @ meshmakers!");
        result.Should().MatchRegex("^[A-Za-z0-9._-]*$");
        result.Should().Be("MicrosoftEntraIDmeshmakers");
    }
}
