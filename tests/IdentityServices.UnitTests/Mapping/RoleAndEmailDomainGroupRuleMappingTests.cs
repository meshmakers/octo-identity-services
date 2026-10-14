using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Xunit;

namespace IdentityServices.UnitTests.Mapping;

public class RoleAndEmailDomainGroupRuleMappingTests
{
    [Fact]
    public void Role_ToDto_UsesRtIdAsId()
    {
        var role = MappingSampleFactory.Role();

        var dto = role.ToDto();

        dto.Id.Should().Be(role.RtId.ToString());
        dto.Name.Should().Be("UserManagement");
    }

    [Fact]
    public void Role_RoundTrip_PreservesName()
    {
        var original = MappingSampleFactory.Role();

        original.ToDto().ToEntity().Name.Should().Be(original.Name);
    }

    [Fact]
    public void Role_ApplyTo_RenamesButKeepsIdAndNormalizedName()
    {
        var role = MappingSampleFactory.Role();
        var originalRtId = role.RtId;

        new RoleDto { Id = "000000000000000000000001", Name = "Renamed" }.ApplyTo(role);

        role.Name.Should().Be("Renamed");
        role.RtId.Should().Be(originalRtId);
        role.NormalizedName.Should().Be("USERMANAGEMENT");
    }

    [Fact]
    public void EmailDomainGroupRule_ToDto_MapsAllFields()
    {
        var rule = MappingSampleFactory.EmailDomainGroupRule();

        var dto = rule.ToDto();

        dto.RtId.Should().Be(rule.RtId);
        dto.EmailDomainPattern.Should().Be("example.com");
        dto.TargetGroupRtId.Should().Be(rule.TargetGroupRtId);
        dto.Description.Should().Be("Everybody from example.com");
    }

    [Fact]
    public void EmailDomainGroupRule_RoundTrip_PreservesEverythingButTheId()
    {
        var original = MappingSampleFactory.EmailDomainGroupRule();

        var roundTripped = original.ToDto().ToEntity();

        roundTripped.EmailDomainPattern.Should().Be(original.EmailDomainPattern);
        roundTripped.TargetGroupRtId.Should().Be(original.TargetGroupRtId);
        roundTripped.Description.Should().Be(original.Description);
        roundTripped.RtId.Should().NotBe(original.RtId);
    }
}
