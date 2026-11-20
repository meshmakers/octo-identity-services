using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Runtime.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.UnitTests.Methods;

/// <summary>
///     How the identity provider methods resolve the concrete provider type from the CK type id of a method request. The
///     REST facades send the version-less id, the GraphQL gateway sends the full name of the concrete type's RtCkId, which
///     carries the element version; a tenant may hold a newer System.Identity than the service embeds, so any element
///     version and any model version resolve to the same type.
/// </summary>
public class IdentityProviderMethodSupportTests
{
    [Theory]
    [InlineData("System.Identity/OpenLdapIdentityProvider")]
    [InlineData("System.Identity/OpenLdapIdentityProvider-1")]
    [InlineData("System.Identity/OpenLdapIdentityProvider-2")]
    [InlineData("System.Identity/OpenLdapIdentityProvider-17")]
    [InlineData("System.Identity-3.8.0/OpenLdapIdentityProvider-1")]
    [InlineData("System.Identity@3/OpenLdapIdentityProvider-2")]
    [InlineData("system.identity/openldapidentityprovider-1")]
    public void EveryFormOfTheConcreteTypeResolves(string requestedCkTypeId)
    {
        var resolved = IdentityProviderMethodSupport.ProviderTypeOf(requestedCkTypeId);

        resolved.Should().NotBeNull(requestedCkTypeId);
        resolved!.Value.Type.Should().Be<RtOpenLdapIdentityProvider>();
        resolved.Value.CkTypeId.Should().Be(RtEntityExtensions.GetRtCkTypeId<RtOpenLdapIdentityProvider>());
    }

    [Fact]
    public void TheGatewayFormOfEveryProviderType_ResolvesToThatType()
    {
        Resolves<RtGoogleIdentityProvider>();
        Resolves<RtMicrosoftIdentityProvider>();
        Resolves<RtFacebookIdentityProvider>();
        Resolves<RtAzureEntraIdIdentityProvider>();
        Resolves<RtMicrosoftAdIdentityProvider>();
        Resolves<RtOpenLdapIdentityProvider>();
        Resolves<RtOctoTenantIdentityProvider>();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("OpenLdapIdentityProvider-1")]
    [InlineData("/OpenLdapIdentityProvider-1")]
    [InlineData("System.Identity/IdentityProvider")]
    [InlineData("System.Identity/IdentityProvider-1")]
    [InlineData("System.Identity/OpenLdapIdentityProvider-")]
    [InlineData("System.Identity/OpenLdapIdentityProvider-x")]
    [InlineData("System.Identity/OpenLdapIdentityProvider-1-1")]
    [InlineData("System.Identity/-1")]
    [InlineData("System.IdentityX/OpenLdapIdentityProvider-1")]
    [InlineData("Other.Model/OpenLdapIdentityProvider-1")]
    [InlineData("System.Identity/Role-1")]
    public void AnythingElse_IsNoProviderType(string? requestedCkTypeId)
    {
        IdentityProviderMethodSupport.ProviderTypeOf(requestedCkTypeId).Should().BeNull(requestedCkTypeId);
    }

    private static void Resolves<T>() where T : RtIdentityProvider, new()
    {
        var gatewayCkTypeId = RtEntityExtensions.GetRtCkTypeId<T>().FullName;
        gatewayCkTypeId.Should().NotBe(IdentityProviderMethodSupport.CkTypeIdOf<T>(),
            "the gateway form carries the element version");

        IdentityProviderMethodSupport.ProviderTypeOf(gatewayCkTypeId)?.Type.Should().Be<T>(gatewayCkTypeId);
        IdentityProviderMethodSupport.ProviderTypeOf(gatewayCkTypeId).Should().NotBeNull(gatewayCkTypeId);
    }
}
