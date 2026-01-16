using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Services;

public class UserManagementServiceTests
{
    private readonly UserManager<RtUser> _userManager;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly ICredentialGenerator _credentialGenerator;
    private readonly ILogger<UserManagementService> _logger;
    private readonly UserManagementService _sut;

    public UserManagementServiceTests()
    {
        var userStore = Substitute.For<IUserStore<RtUser>>();
        _userManager = Substitute.For<UserManager<RtUser>>(
            userStore, null, null, null, null, null, null, null, null);

        var roleStore = Substitute.For<IRoleStore<RtRole>>();
        _roleManager = Substitute.For<RoleManager<RtRole>>(
            roleStore, null, null, null, null);

        _credentialGenerator = Substitute.For<ICredentialGenerator>();
        _logger = Substitute.For<ILogger<UserManagementService>>();

        _sut = new UserManagementService(
            _logger, _userManager, _roleManager, _credentialGenerator);
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenUsersExist_ThrowsUsersAlreadyConfiguredException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        var existingUsers = new List<RtUser> { new RtUser() }.AsQueryable();
        _userManager.Users.Returns(existingUsers);

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UsersAlreadyConfiguredException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenEmailMissing_ThrowsUserManagementException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UserManagementException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenEmailNull_ThrowsUserManagementException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = null!, Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UserManagementException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenPasswordMissing_ThrowsUserManagementException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UserManagementException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenPasswordNull_ThrowsUserManagementException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = null! };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UserManagementException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenPasswordTooWeak_ThrowsUserManagementException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "weak" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword("weak").Returns(false);

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UserManagementException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenValid_CreatesUserWithCorrectCredentials()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Success);

        SetupAllRequiredRoles();

        _userManager.AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>())
            .Returns(IdentityResult.Success);

        // Act
        await _sut.CreateAdminUserAsync(dto);

        // Assert
        await _userManager.Received(1).CreateAsync(
            Arg.Is<RtUser>(u => u.Email == dto.EMail && u.UserName == dto.EMail),
            dto.Password);
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenValid_AssignsAllRequiredRoles()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Success);

        SetupAllRequiredRoles();

        _userManager.AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>())
            .Returns(IdentityResult.Success);

        // Act
        await _sut.CreateAdminUserAsync(dto);

        // Assert
        await _userManager.Received(10).AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>());
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenRoleNotFound_ThrowsUserManagementException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Success);

        // Don't setup roles - they will not be found
        _roleManager.FindByNameAsync(Arg.Any<string>()).Returns((RtRole?)null);

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UserManagementException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenUserAlreadyExists_DoesNotCreateNewUser()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        var existingUser = new RtUser { UserName = dto.EMail, Email = dto.EMail };

        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns(existingUser);

        // Act
        await _sut.CreateAdminUserAsync(dto);

        // Assert
        await _userManager.DidNotReceive().CreateAsync(Arg.Any<RtUser>(), Arg.Any<string>());
    }

    private void SetupAllRequiredRoles()
    {
        var roles = new[]
        {
            CommonConstants.TenantManagementRole,
            CommonConstants.UserManagementRole,
            CommonConstants.DevelopmentRole,
            CommonConstants.CommunicationManagementRole,
            CommonConstants.BotManagementRole,
            CommonConstants.AdminPanelManagementRole,
            CommonConstants.DashboardViewerRole,
            CommonConstants.DashboardManagementRole,
            CommonConstants.ReportingManagementRole,
            CommonConstants.ReportingViewerRole
        };

        foreach (var roleName in roles)
        {
            _roleManager.FindByNameAsync(roleName)
                .Returns(new RtRole { Name = roleName, NormalizedName = roleName.ToUpperInvariant() });
        }
    }
}
