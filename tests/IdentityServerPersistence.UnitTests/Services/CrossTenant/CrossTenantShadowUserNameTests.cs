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

    private static Func<string, Task<bool>> Registry(params string[] tenantIds)
    {
        var set = new HashSet<string>(tenantIds, StringComparer.OrdinalIgnoreCase);
        return t => Task.FromResult(set.Contains(t));
    }

    [Fact]
    public async Task GetSourceChain_NestedShadowName_YieldsEveryTierNearestFirst()
    {
        var chain = await CrossTenantShadowUserName.GetSourceChainAsync(
            "xt_karlplus_xt_meshmakers_gerald@x.com", Registry("karlplus", "meshmakers"));

        chain.Should().Equal(
            ("karlplus", "xt_meshmakers_gerald@x.com"),
            ("meshmakers", "gerald@x.com"));
    }

    [Theory]
    [InlineData("gerald")]
    [InlineData("xt_")]
    [InlineData("xt_meshmakers")]
    [InlineData("xt_meshmakers_")]
    [InlineData("xt__gerald")]
    [InlineData(null)]
    public async Task GetSourceChain_NonShadowOrMalformedName_YieldsNothing(string? userName)
    {
        (await CrossTenantShadowUserName.GetSourceChainAsync(userName, Registry("meshmakers", "")))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task GetSourceChain_UserNameWithUnderscores_KeepsThemInTheUserPart()
    {
        (await CrossTenantShadowUserName.GetSourceChainAsync("xt_meshmakers_first_last", Registry("meshmakers")))
            .Should().Equal(("meshmakers", "first_last"));
    }

    [Fact]
    public async Task GetSourceChain_TenantIdWithUnderscore_SplitsAtTheRegisteredTenant()
    {
        (await CrossTenantShadowUserName.GetSourceChainAsync("xt_tenant_a_first_last", Registry("tenant_a")))
            .Should().Equal(("tenant_a", "first_last"));
    }

    [Theory]
    // tenant "evil_xt", user "meshmakers_gerald"
    [InlineData("evil_xt", "meshmakers_gerald")]
    // tenant "evil_xt_meshmakers", user "gerald"
    [InlineData("evil_xt_meshmakers", "gerald")]
    public async Task GetSourceChain_UnderscoreTenantCannotSpoofANestedChain(string tenant, string user)
    {
        var name = CrossTenantShadowUserName.Build(tenant, user);
        name.Should().Be("xt_evil_xt_meshmakers_gerald");

        (await CrossTenantShadowUserName.GetSourceChainAsync(name, Registry(tenant, "meshmakers")))
            .Should().Equal((tenant, user));
    }

    [Fact]
    public async Task GetSourceChain_AmbiguousTenantPrefix_YieldsNothing()
    {
        (await CrossTenantShadowUserName.GetSourceChainAsync(
                "xt_evil_xt_meshmakers_gerald", Registry("evil", "evil_xt", "meshmakers")))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task GetSourceChain_UnregisteredTenant_YieldsNothing()
    {
        (await CrossTenantShadowUserName.GetSourceChainAsync("xt_deleted_gerald", Registry("meshmakers")))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task GetSourceChain_AmbiguityDeeperDown_KeepsTheUnambiguousTiers()
    {
        (await CrossTenantShadowUserName.GetSourceChainAsync(
                "xt_karlplus_xt_evil_xt_meshmakers_gerald", Registry("karlplus", "evil", "evil_xt", "meshmakers")))
            .Should().Equal(("karlplus", "xt_evil_xt_meshmakers_gerald"));
    }

    [Fact]
    public async Task GetRootIdentity_UnwindsToTheHomeIdentity()
    {
        var registry = Registry("karlplus", "meshmakers");
        (await CrossTenantShadowUserName.GetRootIdentityAsync("karlplus", "xt_meshmakers_gerald", registry))
            .Should().Be(("meshmakers", "gerald"));
        (await CrossTenantShadowUserName.GetRootIdentityAsync("meshmakers", "gerald", registry))
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
