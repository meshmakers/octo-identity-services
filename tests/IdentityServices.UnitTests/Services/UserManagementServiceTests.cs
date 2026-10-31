using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
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
    private readonly IGroupStore _groupStore;
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

        _groupStore = Substitute.For<IGroupStore>();
        _credentialGenerator = Substitute.For<ICredentialGenerator>();
        _logger = Substitute.For<ILogger<UserManagementService>>();

        _sut = new UserManagementService(
            _logger, _userManager, _roleManager, _groupStore, _credentialGenerator);
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
        await _userManager.Received(13).AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>());
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenValid_GrantsFileRolesLikeReportingRoles()
    {
        // AB#6180: the initial tenant administrator gets FileManagement/FileViewer like the Reporting roles.
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Success);
        SetupAllRequiredRoles();
        _userManager.AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>())
            .Returns(IdentityResult.Success);

        await _sut.CreateAdminUserAsync(dto);

        await _userManager.Received(1).AddToRoleAsync(Arg.Any<RtUser>(), "FileManagement");
        await _userManager.Received(1).AddToRoleAsync(Arg.Any<RtUser>(), "FileViewer");
        await _userManager.Received(1).AddToRoleAsync(Arg.Any<RtUser>(), CommonConstants.ReportingManagementRole);
        await _userManager.Received(1).AddToRoleAsync(Arg.Any<RtUser>(), CommonConstants.ReportingViewerRole);
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenFileRolesAreMissing_StillGrantsTheOtherRoles()
    {
        // AB#6180: a tenant seeded by an older bootstrap blueprint has no file roles yet; the admin must still
        // get every other role (the one-time file role grant adds the file roles later).
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Success);
        SetupAllRequiredRoles();
        _roleManager.FindByNameAsync(IdentityServerPersistence.IdentityServiceConstants.FileManagementRole)
            .Returns((RtRole?)null);
        _roleManager.FindByNameAsync(IdentityServerPersistence.IdentityServiceConstants.FileViewerRole)
            .Returns((RtRole?)null);
        _userManager.AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>())
            .Returns(IdentityResult.Success);

        await _sut.CreateAdminUserAsync(dto);

        await _userManager.Received(11).AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>());
        await _userManager.DidNotReceive().AddToRoleAsync(Arg.Any<RtUser>(), "FileManagement");
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenValid_GrantsSecretManagementLikeAdminPanelManagement()
    {
        // AB#5544: the initial tenant administrator gets SecretManagement like AdminPanelManagement.
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Success);
        SetupAllRequiredRoles();
        _userManager.AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>())
            .Returns(IdentityResult.Success);

        await _sut.CreateAdminUserAsync(dto);

        await _userManager.Received(1).AddToRoleAsync(Arg.Any<RtUser>(), "SecretManagement");
        await _userManager.Received(1).AddToRoleAsync(Arg.Any<RtUser>(), CommonConstants.AdminPanelManagementRole);
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenSecretManagementRoleIsMissing_StillGrantsTheOtherRoles()
    {
        // AB#5544: a tenant seeded by a bootstrap blueprint older than 1.7.0 has no SecretManagement role; the
        // first administrator must still get every other role (the one-time grant adds it later).
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Success);
        SetupAllRequiredRoles();
        _roleManager.FindByNameAsync(CommonConstants.SecretManagementRole).Returns((RtRole?)null);
        _userManager.AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>())
            .Returns(IdentityResult.Success);

        await _sut.CreateAdminUserAsync(dto);

        await _userManager.Received(12).AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>());
        await _userManager.DidNotReceive().AddToRoleAsync(Arg.Any<RtUser>(), CommonConstants.SecretManagementRole);
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

    [Fact]
    public async Task CreateAdminUserAsync_WhenCreateAsyncFails_ThrowsUserManagementException()
    {
        // Arrange
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password).Returns(true);
        _userManager.FindByNameAsync(dto.EMail).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password)
            .Returns(IdentityResult.Failed(new IdentityError { Code = "DuplicateUserName", Description = "User already exists" }));

        // Act
        var act = () => _sut.CreateAdminUserAsync(dto);

        // Assert
        await act.Should().ThrowAsync<UserManagementException>();
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenValid_AddsTheAdministratorToTenantOwners()
    {
        // AB#7946: TenantOwners carries the roles the direct grants lack (DataModelManagement, StreamData*); without
        // the membership the first administrator cannot add anyone to TenantOwners under the role change guard.
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        var group = new RtGroup { RtId = OctoObjectId.GenerateNewId(), GroupName = "TenantOwners" };
        ArrangeValidSetup(dto);
        _groupStore.FindByNameAsync("TENANTOWNERS").Returns(group);
        _groupStore.GetMemberUserIdsAsync(group.RtId).Returns(new List<string>());
        RtUser? created = null;
        _userManager.CreateAsync(Arg.Do<RtUser>(u => { u.RtId = OctoObjectId.GenerateNewId(); created = u; }), dto.Password)
            .Returns(IdentityResult.Success);

        await _sut.CreateAdminUserAsync(dto);

        await _groupStore.Received(1).AddMemberUserAsync(group.RtId, created!.RtId.ToString());
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenAlreadyMemberOfTenantOwners_DoesNotAddTheMembershipAgain()
    {
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        var group = new RtGroup { RtId = OctoObjectId.GenerateNewId(), GroupName = "TenantOwners" };
        ArrangeValidSetup(dto);
        var userId = OctoObjectId.GenerateNewId();
        _userManager.CreateAsync(Arg.Do<RtUser>(u => u.RtId = userId), dto.Password).Returns(IdentityResult.Success);
        _groupStore.FindByNameAsync("TENANTOWNERS").Returns(group);
        _groupStore.GetMemberUserIdsAsync(group.RtId).Returns(new List<string> { userId.ToString() });

        await _sut.CreateAdminUserAsync(dto);

        await _groupStore.DidNotReceive().AddMemberUserAsync(Arg.Any<OctoObjectId>(), Arg.Any<string>());
    }

    [Fact]
    public async Task CreateAdminUserAsync_WhenTenantOwnersGroupIsMissing_StillCreatesTheAdministratorWithDirectRoles()
    {
        var dto = new AdminUserDto { EMail = "admin@test.com", Password = "SecurePass123!" };
        ArrangeValidSetup(dto);
        _groupStore.FindByNameAsync("TENANTOWNERS").Returns((RtGroup?)null);

        await _sut.CreateAdminUserAsync(dto);

        await _userManager.Received(13).AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>());
        await _groupStore.DidNotReceive().AddMemberUserAsync(Arg.Any<OctoObjectId>(), Arg.Any<string>());
    }

    private void ArrangeValidSetup(AdminUserDto dto)
    {
        _userManager.Users.Returns(Enumerable.Empty<RtUser>().AsQueryable());
        _credentialGenerator.CheckPassword(dto.Password!).Returns(true);
        _userManager.FindByNameAsync(dto.EMail!).Returns((RtUser?)null);
        _userManager.CreateAsync(Arg.Any<RtUser>(), dto.Password!).Returns(IdentityResult.Success);
        SetupAllRequiredRoles();
        _userManager.AddToRoleAsync(Arg.Any<RtUser>(), Arg.Any<string>()).Returns(IdentityResult.Success);
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
            CommonConstants.SecretManagementRole,
            CommonConstants.DashboardViewerRole,
            CommonConstants.DashboardManagementRole,
            CommonConstants.ReportingManagementRole,
            CommonConstants.ReportingViewerRole,
            IdentityServerPersistence.IdentityServiceConstants.FileManagementRole,
            IdentityServerPersistence.IdentityServiceConstants.FileViewerRole
        };

        foreach (var roleName in roles)
        {
            _roleManager.FindByNameAsync(roleName)
                .Returns(new RtRole { Name = roleName, NormalizedName = roleName.ToUpperInvariant() });
        }
    }
}
