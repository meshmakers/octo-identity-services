using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

public class SetupApiControllerTests
{
    private readonly UserManager<RtUser> _userManager;
    private readonly IUserManagementService _userManagementService;
    private readonly ILogger<SetupApiController> _logger;
    private readonly SetupApiController _sut;

    public SetupApiControllerTests()
    {
        var userStore = Substitute.For<IUserStore<RtUser>>();
        _userManager = Substitute.For<UserManager<RtUser>>(
            userStore, null, null, null, null, null, null, null, null);

        _userManagementService = Substitute.For<IUserManagementService>();
        _logger = Substitute.For<ILogger<SetupApiController>>();

        _sut = new SetupApiController(_userManager, _userManagementService, _logger);
    }

    #region GetStatus Tests

    [Fact]
    public void GetStatus_WhenNoUsersExist_ReturnsOkWithSetupRequired()
    {
        // Arrange
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());

        // Act
        var result = _sut.GetStatus();

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<SetupStatusDto>().Subject;
        dto.SetupRequired.Should().BeTrue();
    }

    [Fact]
    public void GetStatus_WhenUsersExist_ReturnsNotFound()
    {
        // Arrange
        var existingUsers = new List<RtUser> { new() }.AsQueryable();
        _userManager.Users.Returns(existingUsers);

        // Act
        var result = _sut.GetStatus();

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    #endregion

    #region CreateAdmin Tests

    [Fact]
    public async Task CreateAdmin_WhenUsersExist_ReturnsNotFound()
    {
        // Arrange
        var existingUsers = new List<RtUser> { new() }.AsQueryable();
        _userManager.Users.Returns(existingUsers);
        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        // Act
        var result = await _sut.CreateAdmin(request);

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task CreateAdmin_WhenPasswordMismatch_ReturnsErrorResult()
    {
        // Arrange
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "DifferentPass123!"
        };

        // Act
        var result = await _sut.CreateAdmin(request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<SetupResultDto>().Subject;
        dto.Success.Should().BeFalse();
        dto.ErrorMessage.Should().Be("Passwords do not match");
    }

    [Fact]
    public async Task CreateAdmin_WhenValid_ReturnsSuccess()
    {
        // Arrange
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        // Act
        var result = await _sut.CreateAdmin(request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<SetupResultDto>().Subject;
        dto.Success.Should().BeTrue();
    }

    [Fact]
    public async Task CreateAdmin_WhenValid_CallsUserManagementService()
    {
        // Arrange
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        // Act
        await _sut.CreateAdmin(request);

        // Assert
        await _userManagementService.Received(1).CreateAdminUserAsync(
            Arg.Is<AdminUserDto>(d => d.EMail == "admin@test.com" && d.Password == "SecurePass123!"));
    }

    [Fact]
    public async Task CreateAdmin_WhenUsersAlreadyConfigured_ReturnsNotFound()
    {
        // Arrange
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        _userManagementService
            .When(x => x.CreateAdminUserAsync(Arg.Any<AdminUserDto>()))
            .Throw(UsersAlreadyConfiguredException.UsersConfigured());

        // Act
        var result = await _sut.CreateAdmin(request);

        // Assert
        result.Should().BeOfType<NotFoundResult>();
    }

    [Fact]
    public async Task CreateAdmin_WhenServiceThrows_ReturnsErrorResult()
    {
        // Arrange
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        var request = new SetupAdminRequestDto
        {
            Email = "admin@test.com",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        _userManagementService
            .When(x => x.CreateAdminUserAsync(Arg.Any<AdminUserDto>()))
            .Throw(UserManagementException.PasswordComplexityCheckFailed());

        // Act
        var result = await _sut.CreateAdmin(request);

        // Assert
        var okResult = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = okResult.Value.Should().BeOfType<SetupResultDto>().Subject;
        dto.Success.Should().BeFalse();
        dto.ErrorMessage.Should().NotBeNullOrEmpty();
    }

    #endregion
}
