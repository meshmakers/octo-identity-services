using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using NSubstitute;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#7765 (review finding M3): every password change rotates the security stamp, revokes the user's
///     tokens and authorizations in the current tenant and writes one audit entry without secrets.
/// </summary>
public class UserCredentialChangeServiceTests
{
    private const string TenantId = "tenant-a";

    private readonly UserManager<RtUser> _userManager = Substitute.For<UserManager<RtUser>>(
        Substitute.For<IUserStore<RtUser>>(), null, null, null, null, null, null, null, null);

    private readonly IOpenIddictTokenStore<RtOAuthToken> _tokenStore = Substitute.For<IOpenIddictTokenStore<RtOAuthToken>>();

    private readonly IOpenIddictAuthorizationStore<RtOAuthAuthorization> _authorizationStore =
        Substitute.For<IOpenIddictAuthorizationStore<RtOAuthAuthorization>>();

    private readonly IMultiTenancyResolverService _tenantResolver = Substitute.For<IMultiTenancyResolverService>();
    private readonly CapturingLogger<UserCredentialChangeService> _logger = new();
    private readonly UserCredentialChangeService _sut;
    private readonly RtUser _user = new RtUserBuilder().WithUserName("alice").Build();

    public UserCredentialChangeServiceTests()
    {
        _tenantResolver.GetTenantId().Returns(TenantId);
        _userManager.UpdateSecurityStampAsync(Arg.Any<RtUser>()).Returns(IdentityResult.Success);
        _tokenStore.RevokeBySubjectAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(new ValueTask<long>(2));
        _authorizationStore.RevokeBySubjectAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new ValueTask<long>(1));
        _sut = new UserCredentialChangeService(_userManager, _tokenStore, _authorizationStore, _tenantResolver, _logger);
    }

    [Fact]
    public async Task OnPasswordChanged_RotatesStampAndRevokesTokensAndAuthorizationsOfTheSubject()
    {
        await _sut.OnPasswordChangedAsync(_user, PasswordChangePath.ChangePassword, "alice", TestContext.Current.CancellationToken);

        await _userManager.Received(1).UpdateSecurityStampAsync(_user);
        await _tokenStore.Received(1).RevokeBySubjectAsync(_user.RtId.ToString(), Arg.Any<CancellationToken>());
        await _authorizationStore.Received(1).RevokeBySubjectAsync(_user.RtId.ToString(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task OnPasswordChanged_WritesOneAuditEntryNamingTenantSubjectActorAndPath()
    {
        await _sut.OnPasswordChangedAsync(_user, PasswordChangePath.AdminResetPassword, "admin", TestContext.Current.CancellationToken);

        _logger.Messages.Should().ContainSingle();
        var text = _logger.AllText;
        text.Should().Contain(TenantId).And.Contain(_user.RtId.ToString())
            .And.Contain("admin").And.Contain(nameof(PasswordChangePath.AdminResetPassword));
        text.Should().NotContain(_user.PasswordHash ?? "no-hash-set");
    }

    [Fact]
    public async Task OnPasswordChanged_WithoutActingUser_LabelsTheEntryAnonymous()
    {
        await _sut.OnPasswordChangedAsync(_user, PasswordChangePath.TokenResetPassword, null, TestContext.Current.CancellationToken);

        _logger.AllText.Should().Contain("anonymous");
    }

    [Fact]
    public async Task OnPasswordChanged_WhenStampUpdateFails_ThrowsInsteadOfReportingSuccess()
    {
        _userManager.UpdateSecurityStampAsync(Arg.Any<RtUser>())
            .Returns(IdentityResult.Failed(new IdentityError { Description = "boom" }));

        var act = () => _sut.OnPasswordChangedAsync(_user, PasswordChangePath.SetPassword, "alice", TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task OnPasswordChanged_WhenRevocationFails_Propagates()
    {
        _tokenStore.RevokeBySubjectAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<ValueTask<long>>(_ => throw new InvalidOperationException("store down"));

        var act = () => _sut.OnPasswordChangedAsync(_user, PasswordChangePath.ChangePassword, "alice", TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }
}
