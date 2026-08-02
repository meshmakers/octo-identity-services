using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
/// The identity-provider write path (shared by the Studio UI, octo-cli and the MCP server)
/// must reject provider names that would later break just-in-time user provisioning. A name
/// containing spaces (e.g. "Microsoft Entra ID") produced an invalid user name and surfaced
/// as "Failed to create user account" only after a successful external login.
/// </summary>
public class IdentityProviderNameValidationTests
{
    [Theory]
    [InlineData("AzureEntraId")]
    [InlineData("Google")]
    [InlineData("Entra-ID")]
    [InlineData("my.provider_1")]
    [InlineData("AAD")]
    public void IsProviderNameValid_AcceptsSafeNames(string name)
    {
        IdentityProvidersController.IsProviderNameValid(name).Should().BeTrue();
    }

    [Theory]
    [InlineData("Microsoft Entra ID")]   // spaces
    [InlineData("Azure AD (prod)")]      // spaces + parentheses
    [InlineData("Entra ID")]
    [InlineData("Müller")]               // non-ASCII letter
    [InlineData("provider@tenant")]      // '@' not allowed
    [InlineData("a b")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void IsProviderNameValid_RejectsUnsafeNames(string? name)
    {
        IdentityProvidersController.IsProviderNameValid(name).Should().BeFalse();
    }
}
