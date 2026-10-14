using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Xunit;

namespace IdentityServices.UnitTests.Mapping;

public class UserMappingTests
{
    [Fact]
    public void ToDto_MapsIdentityAndProfileFields()
    {
        var user = MappingSampleFactory.UserWithLogins();

        var dto = user.ToDto();

        dto.UserId.Should().Be(user.RtId.ToString());
        dto.Name.Should().Be("jane.doe");
        dto.FirstName.Should().Be("Jane");
        dto.LastName.Should().Be("Doe");
        dto.Email.Should().Be("jane@example.com");
        dto.ResetPasswordOnLogin.Should().BeTrue();
    }

    [Fact]
    public void ToDto_ExternalLogin_WithoutDisplayName_FallsBackToLoginProvider()
    {
        var dto = MappingSampleFactory.UserWithLogins().ToDto();

        dto.ExternalLogins.Should().BeEquivalentTo(new List<ExternalLoginDto>
        {
            new() { LoginProvider = "tenant:google", ProviderKey = "google-key", ProviderDisplayName = "Google" },
            new() { LoginProvider = "tenant:ldap", ProviderKey = "ldap-key", ProviderDisplayName = "tenant:ldap" }
        }, options => options.WithStrictOrdering());
    }

    [Fact]
    public void ToDto_WithoutLogins_YieldsEmptyList()
    {
        var user = MappingSampleFactory.UserWithLogins();
        user.UserLogins = null!;

        user.ToDto().ExternalLogins.Should().NotBeNull().And.BeEmpty();
    }

    [Fact]
    public void RoundTrip_PreservesEveryFieldTheDtoCarries()
    {
        var original = MappingSampleFactory.UserWithLogins();

        var roundTripped = original.ToDto().ToEntity();

        roundTripped.UserName.Should().Be(original.UserName);
        roundTripped.FirstName.Should().Be(original.FirstName);
        roundTripped.LastName.Should().Be(original.LastName);
        roundTripped.Email.Should().Be(original.Email);
        roundTripped.ResetPasswordOnLogin.Should().Be(original.ResetPasswordOnLogin);
    }

    [Fact]
    public void ToEntity_NeverTakesIdOrLoginsFromTheRequest()
    {
        var dto = new UserDto
        {
            UserId = "000000000000000000000001",
            Name = "john",
            ExternalLogins = [new ExternalLoginDto { LoginProvider = "forged", ProviderKey = "forged" }]
        };

        var entity = dto.ToEntity();

        entity.RtId.ToString().Should().NotBe(dto.UserId);
        entity.UserLogins.Should().BeNullOrEmpty();
    }

    [Fact]
    public void ApplyTo_OverwritesProfileFields_AndKeepsIdentityAndSecurityState()
    {
        var user = MappingSampleFactory.UserWithLogins();
        var originalRtId = user.RtId;
        user.PasswordHash = "hash";
        user.SecurityStamp = "stamp";

        new UserDto { Name = "renamed", FirstName = null, Email = "new@example.com" }.ApplyTo(user);

        user.UserName.Should().Be("renamed");
        user.FirstName.Should().BeNull();
        user.LastName.Should().BeNull();
        user.Email.Should().Be("new@example.com");
        user.ResetPasswordOnLogin.Should().BeFalse();
        user.RtId.Should().Be(originalRtId);
        user.PasswordHash.Should().Be("hash");
        user.SecurityStamp.Should().Be("stamp");
        user.UserLogins.Should().HaveCount(2);
    }
}
