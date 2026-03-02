using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Infrastructure.CredentialGenerator;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserManagementService(
    ILogger<UserManagementService> logger,
    UserManager<RtUser> userManager,
    RoleManager<RtRole> roleManager,
    ICredentialGenerator credentialGenerator) : IUserManagementService
{
    public async Task CreateAdminUserAsync(AdminUserDto adminUserDto)
    {
        if (userManager.Users.Any())
        {
            throw UsersAlreadyConfiguredException.UsersConfigured();
        }

        if (string.IsNullOrWhiteSpace(adminUserDto.EMail))
        {
            logger.LogError("E-Mail value is missing");
            throw UserManagementException.EMailMissing();
        }

        if (string.IsNullOrWhiteSpace(adminUserDto.Password))
        {
            logger.LogError("Password value is missing");
            throw UserManagementException.PasswordMissing();
        }

        if (!credentialGenerator.CheckPassword(adminUserDto.Password))
        {
            logger.LogError("The password does not comply with the minimum requirements");
            throw UserManagementException.PasswordComplexityCheckFailed();
        }

        var adminUser = await userManager.FindByNameAsync(adminUserDto.EMail);
        if (adminUser == null)
        {
            adminUser = new RtUser { UserName = adminUserDto.EMail, Email = adminUserDto.EMail };

            var result = await userManager.CreateAsync(adminUser, adminUserDto.Password);
            if (!result.Succeeded)
            {
                throw UserManagementException.UserCreationFailed(result.Errors);
            }

            await TryAddRole(adminUser, CommonConstants.TenantManagementRole);
            await TryAddRole(adminUser, CommonConstants.UserManagementRole);
            await TryAddRole(adminUser, CommonConstants.DevelopmentRole);
            await TryAddRole(adminUser, CommonConstants.CommunicationManagementRole);
            await TryAddRole(adminUser, CommonConstants.BotManagementRole);
            await TryAddRole(adminUser, CommonConstants.AdminPanelManagementRole);
            await TryAddRole(adminUser, CommonConstants.DashboardViewerRole);
            await TryAddRole(adminUser, CommonConstants.DashboardManagementRole);
            await TryAddRole(adminUser, CommonConstants.ReportingManagementRole);
            await TryAddRole(adminUser, CommonConstants.ReportingViewerRole);
        }
    }

    private async Task TryAddRole(RtUser user, string roleName)
    {
        var rtRole = await roleManager.FindByNameAsync(roleName);
        if (rtRole == null)
        {
            throw UserManagementException.RoleNotFound(roleName);
        }

        await userManager.AddToRoleAsync(user, rtRole.Name);
    }
}