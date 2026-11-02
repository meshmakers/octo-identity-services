using FluentAssertions;
using IdentityServerPersistence.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.CrossTenant;

/// <summary>
///     AB#5708: cross-tenant shadow users (<c>xt_</c>) never get a local password — it would be a second
///     way into the tenant that bypasses the home tenant's login.
/// </summary>
public class ShadowUserPasswordValidatorTests
{
    private readonly ShadowUserPasswordValidator _sut = new();

    private static UserManager<RtUser> UserManager() => new(
        Substitute.For<IUserStore<RtUser>>(),
        Options.Create(new IdentityOptions()),
        new PasswordHasher<RtUser>(),
        [],
        [],
        new UpperInvariantLookupNormalizer(),
        new IdentityErrorDescriber(),
        null!,
        NullLogger<UserManager<RtUser>>.Instance);

    [Theory]
    [InlineData("xt_meshmakers_gerald")]
    [InlineData("xt_karlplus_xt_meshmakers_gerald")]
    [InlineData("XT_Meshmakers_Gerald")]
    public async Task ShadowUser_IsRefused(string userName)
    {
        var result = await _sut.ValidateAsync(UserManager(), new RtUser { UserName = userName }, "Str0ng!Passw0rd");

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Code.Should().Be(ShadowUserPasswordValidator.ErrorCode);
        result.Errors.Single().Description.Should().Be(ShadowUserPasswordValidator.ErrorMessage);
    }

    [Theory]
    [InlineData("gerald")]
    [InlineData("meshmakers_gerald")]
    [InlineData("Google_xt_user@example.com")]
    [InlineData("xt")]
    public async Task LocalUser_IsAccepted(string userName)
    {
        var result = await _sut.ValidateAsync(UserManager(), new RtUser { UserName = userName }, "Str0ng!Passw0rd");

        result.Succeeded.Should().BeTrue();
    }
}
