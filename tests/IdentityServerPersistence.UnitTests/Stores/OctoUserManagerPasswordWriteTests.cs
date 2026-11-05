using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Stores;

/// <summary>
///     AB#8018: every password write of <see cref="OctoUserManager" /> revokes the user's tokens <b>before</b> the user is
///     stored, and only for a valid request. The callers revoke again after the write, so a crash between the password
///     write and that second revocation leaves no old refresh token valid.
/// </summary>
public class OctoUserManagerPasswordWriteTests
{
    private const string OldPassword = "Old1!pass";
    private const string NewPassword = "N3w!Passw0rd";

    private readonly IUserPasswordStore<RtUser> _store =
        Substitute.For<IUserPasswordStore<RtUser>, IUserSecurityStampStore<RtUser>>();

    private readonly IUserTokenRevocation _revocation = Substitute.For<IUserTokenRevocation>();
    private readonly IUserTwoFactorTokenProvider<RtUser> _resetTokens = Substitute.For<IUserTwoFactorTokenProvider<RtUser>>();
    private readonly RtUser _user = new RtUserBuilder().WithUserName("alice").Build();
    private string? _storedHash;

    public OctoUserManagerPasswordWriteTests()
    {
        _storedHash = new PasswordHasher<RtUser>().HashPassword(_user, OldPassword);
        _store.GetPasswordHashAsync(_user, Arg.Any<CancellationToken>()).Returns(_ => _storedHash);
        _store.UpdateAsync(_user, Arg.Any<CancellationToken>()).Returns(IdentityResult.Success);
        _resetTokens.ValidateAsync(Arg.Any<string>(), "valid-token", Arg.Any<UserManager<RtUser>>(), _user)
            .Returns(true);
    }

    [Fact]
    public async Task ChangePassword_RevokesBeforeTheUserIsStored()
    {
        var result = await CreateManager(_revocation).ChangePasswordAsync(_user, OldPassword, NewPassword);

        result.Succeeded.Should().BeTrue();
        Received.InOrder(() =>
        {
            _ = _revocation.RevokeAllAsync(_user.RtId.ToString(), Arg.Any<CancellationToken>());
            _ = _store.UpdateAsync(_user, Arg.Any<CancellationToken>());
        });
    }

    [Fact]
    public async Task ChangePassword_WrongCurrentPassword_RevokesNothing_StoresNothing()
    {
        var result = await CreateManager(_revocation).ChangePasswordAsync(_user, "Wr0ng!pass", NewPassword);

        result.Errors.Select(e => e.Code).Should().Equal(nameof(IdentityErrorDescriber.PasswordMismatch));
        await AssertNothingRevokedOrStoredAsync();
    }

    [Fact]
    public async Task ChangePassword_PolicyViolation_RevokesNothing_StoresNothing()
    {
        var result = await CreateManager(_revocation).ChangePasswordAsync(_user, OldPassword, "weak");

        result.Succeeded.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Code == nameof(IdentityErrorDescriber.PasswordTooShort));
        await AssertNothingRevokedOrStoredAsync();
    }

    [Fact]
    public async Task ResetPassword_ValidToken_RevokesBeforeTheUserIsStored()
    {
        var result = await CreateManager(_revocation).ResetPasswordAsync(_user, "valid-token", NewPassword);

        result.Succeeded.Should().BeTrue();
        Received.InOrder(() =>
        {
            _ = _revocation.RevokeAllAsync(_user.RtId.ToString(), Arg.Any<CancellationToken>());
            _ = _store.UpdateAsync(_user, Arg.Any<CancellationToken>());
        });
    }

    [Fact]
    public async Task ResetPassword_InvalidToken_RevokesNothing_SoNobodyCanEndForeignSessions()
    {
        var result = await CreateManager(_revocation).ResetPasswordAsync(_user, "forged-token", NewPassword);

        result.Errors.Select(e => e.Code).Should().Equal(nameof(IdentityErrorDescriber.InvalidToken));
        await AssertNothingRevokedOrStoredAsync();
    }

    [Fact]
    public async Task ResetPassword_PolicyViolation_RevokesNothing_StoresNothing()
    {
        var result = await CreateManager(_revocation).ResetPasswordAsync(_user, "valid-token", "weak");

        result.Succeeded.Should().BeFalse();
        await AssertNothingRevokedOrStoredAsync();
    }

    [Fact]
    public async Task AddPassword_UserWithoutPassword_RevokesBeforeTheUserIsStored()
    {
        _storedHash = null;

        var result = await CreateManager(_revocation).AddPasswordAsync(_user, NewPassword);

        result.Succeeded.Should().BeTrue();
        Received.InOrder(() =>
        {
            _ = _revocation.RevokeAllAsync(_user.RtId.ToString(), Arg.Any<CancellationToken>());
            _ = _store.UpdateAsync(_user, Arg.Any<CancellationToken>());
        });
    }

    [Fact]
    public async Task AddPassword_UserWithPassword_RevokesNothing_StoresNothing()
    {
        var result = await CreateManager(_revocation).AddPasswordAsync(_user, NewPassword);

        result.Errors.Select(e => e.Code).Should().Equal(nameof(IdentityErrorDescriber.UserAlreadyHasPassword));
        await AssertNothingRevokedOrStoredAsync();
    }

    [Fact]
    public async Task FailingRevocation_Throws_AndThePasswordIsNotStored()
    {
        _revocation.RevokeAllAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("token store down"));

        var act = () => CreateManager(_revocation).ChangePasswordAsync(_user, OldPassword, NewPassword);

        await act.Should().ThrowAsync<InvalidOperationException>();
        await _store.DidNotReceive().UpdateAsync(Arg.Any<RtUser>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FailingStoreWrite_AfterTheRevocation_KeepsTheSessionsEnded_AndReportsTheFailure()
    {
        // Accepted (review finding on #234): the revocation must come before the write for crash safety, so a write
        // refused by the store (concurrent user write, user validator) ends the sessions without changing the password.
        _store.UpdateAsync(_user, Arg.Any<CancellationToken>())
            .Returns(IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure()));

        var result = await CreateManager(_revocation).ChangePasswordAsync(_user, OldPassword, NewPassword);

        result.Errors.Select(e => e.Code).Should().Equal(nameof(IdentityErrorDescriber.ConcurrencyFailure));
        await _revocation.Received(1).RevokeAllAsync(_user.RtId.ToString(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task WithoutARevocation_AManagerForAnotherTenantStillWritesThePassword()
    {
        // The manager of CrossTenantSecondFactorVerifier is built without one (it never writes passwords).
        var result = await CreateManager(null).ChangePasswordAsync(_user, OldPassword, NewPassword);

        result.Succeeded.Should().BeTrue();
        await _store.Received(1).UpdateAsync(_user, Arg.Any<CancellationToken>());
    }

    private async Task AssertNothingRevokedOrStoredAsync()
    {
        await _revocation.DidNotReceive().RevokeAllAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _store.DidNotReceive().UpdateAsync(Arg.Any<RtUser>(), Arg.Any<CancellationToken>());
    }

    private OctoUserManager CreateManager(IUserTokenRevocation? revocation)
    {
        var manager = new OctoUserManager(_store, Options.Create(new IdentityOptions()), new PasswordHasher<RtUser>(),
            [], [new PasswordValidator<RtUser>()], new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(),
            Substitute.For<IServiceProvider>(), NullLogger<UserManager<RtUser>>.Instance, revocation);
        manager.RegisterTokenProvider(TokenOptions.DefaultProvider, _resetTokens);
        return manager;
    }
}
