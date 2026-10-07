using FluentAssertions;
using IdentityServerPersistence.Services;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.CrossTenant;

/// <summary>AB#5708: the xt_ naming chain is the identity rule behind shadow-user roles and dedupe.</summary>
public class CrossTenantShadowUserNameTests
{
    [Fact]
    public void Build_ProducesPrefixedName()
    {
        CrossTenantShadowUserName.Build("meshmakers", "gerald").Should().Be("xt_meshmakers_gerald");
    }

    [Theory]
    [InlineData("xt_meshmakers_gerald", true)]
    [InlineData("XT_meshmakers_gerald", true)]
    [InlineData("gerald", false)]
    [InlineData("External_xt_meshmakers_gerald", false)]
    [InlineData(null, false)]
    public void IsShadowUserName_DetectsReservedPrefix(string? userName, bool expected)
    {
        CrossTenantShadowUserName.IsShadowUserName(userName).Should().Be(expected);
    }

    [Fact]
    public void GetSourceChain_NestedShadowName_YieldsEveryTierNearestFirst()
    {
        var chain = CrossTenantShadowUserName.GetSourceChain("xt_karlplus_xt_meshmakers_gerald@x.com");

        chain.Should().Equal(
            ("karlplus", "xt_meshmakers_gerald@x.com"),
            ("meshmakers", "gerald@x.com"));
    }

    [Theory]
    [InlineData("gerald")]
    [InlineData("xt_")]
    [InlineData("xt_meshmakers")]
    [InlineData("xt__gerald")]
    [InlineData(null)]
    public void GetSourceChain_NonShadowOrMalformedName_YieldsNothing(string? userName)
    {
        CrossTenantShadowUserName.GetSourceChain(userName).Should().BeEmpty();
    }

    [Fact]
    public void GetSourceChain_UserNameWithUnderscores_KeepsThemInTheUserPart()
    {
        CrossTenantShadowUserName.GetSourceChain("xt_meshmakers_first_last")
            .Should().Equal(("meshmakers", "first_last"));
    }

    [Fact]
    public void GetRootIdentity_UnwindsToTheHomeIdentity()
    {
        CrossTenantShadowUserName.GetRootIdentity("karlplus", "xt_meshmakers_gerald")
            .Should().Be(("meshmakers", "gerald"));
        CrossTenantShadowUserName.GetRootIdentity("meshmakers", "gerald")
            .Should().Be(("meshmakers", "gerald"));
    }

    [Fact]
    public void IsSameIdentity_ComparesCaseInsensitively()
    {
        CrossTenantShadowUserName.IsSameIdentity(("MeshMakers", "Gerald"), ("meshmakers", "gerald"))
            .Should().BeTrue();
        CrossTenantShadowUserName.IsSameIdentity(("meshmakers", "gerald"), ("karlplus", "gerald"))
            .Should().BeFalse();
    }
}
