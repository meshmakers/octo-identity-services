using FluentAssertions;
using IdentityServerPersistence.Services.SecretManagement;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SecretManagement;

/// <summary>AB#8161: which octosystem mappings get SecretManagement appended to their MappedRoleIds.</summary>
public class TenantOwnersSecretManagementGrantPlannerTests
{
    private const string System = "octosystem";
    private const string Tm = "tm";
    private const string Sm = "sm";

    private static IReadOnlyList<string> Plan(params TenantOwnersGrantMapping[] mappings) =>
        TenantOwnersSecretManagementGrantPlanner.PlanMappings(mappings, System, Tm, Sm);

    [Fact]
    public void OctosystemMappingWithTenantManagement_IsExtended()
    {
        Plan(new TenantOwnersGrantMapping("m1", "octosystem", [Tm, "x"], false)).Should().Equal("m1");
    }

    [Fact]
    public void SourceTenantComparison_IgnoresCase()
    {
        Plan(new TenantOwnersGrantMapping("m1", "OctoSystem", [Tm], false)).Should().Equal("m1");
    }

    [Fact]
    public void MappingOfAnotherSourceTenant_IsNotChanged()
    {
        Plan(new TenantOwnersGrantMapping("m1", "meshmakers", [Tm], false)).Should().BeEmpty();
    }

    [Fact]
    public void MappingWithoutTenantManagement_IsNotChanged()
    {
        Plan(new TenantOwnersGrantMapping("m1", System, ["x"], false)).Should().BeEmpty();
    }

    [Fact]
    public void MappingThatAlreadyHoldsSecretManagement_IsNotChanged()
    {
        Plan(new TenantOwnersGrantMapping("m1", System, [Tm, Sm], false)).Should().BeEmpty();
    }

    [Fact]
    public void TenantOwnersMember_InheritsTheRoleFromTheGroup_AndIsNotChanged()
    {
        Plan(new TenantOwnersGrantMapping("m1", System, [Tm], true)).Should().BeEmpty();
    }

    [Fact]
    public void Result_IsOrdered()
    {
        Plan(
            new TenantOwnersGrantMapping("b", System, [Tm], false),
            new TenantOwnersGrantMapping("a", System, [Tm], false)).Should().Equal("a", "b");
    }
}
