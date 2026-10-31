using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
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
    IGroupStore groupStore,
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
            // Optional like the file roles: a tenant set up from a bootstrap seed older than 1.7.0 has no
            // SecretManagement role yet; the one-time grant (AB#5544) gives it to the administrators later.
            await TryAddRole(adminUser, CommonConstants.SecretManagementRole, required: false);
            await TryAddRole(adminUser, CommonConstants.DashboardViewerRole);
            await TryAddRole(adminUser, CommonConstants.DashboardManagementRole);
            await TryAddRole(adminUser, CommonConstants.ReportingManagementRole);
            await TryAddRole(adminUser, CommonConstants.ReportingViewerRole);
            // Optional: a tenant set up from an older bootstrap seed has no file roles yet; the one-time
            // file role grant (AB#6180) gives them to the Reporting role holders on the next tenant setup.
            await TryAddRole(adminUser, IdentityServiceConstants.FileManagementRole, required: false);
            await TryAddRole(adminUser, IdentityServiceConstants.FileViewerRole, required: false);

            await AddToTenantOwnersAsync(adminUser);
        }
    }

    /// <summary>
    ///     The first administrator also becomes a member of <c>TenantOwners</c>, which carries every non-secret built-in
    ///     role. Without it the administrator holds only the direct roles above and, under the role change guard (grant
    ///     only built-in roles you hold), could not add anyone to <c>TenantOwners</c>. The group is part of the
    ///     bootstrap blueprint; a tenant without it keeps the direct roles only. Idempotent: an existing membership is
    ///     left alone. This is the setup path and does not go through the guarded controllers by design.
    /// </summary>
    private async Task AddToTenantOwnersAsync(RtUser adminUser)
    {
        var group = await groupStore.FindByNameAsync(CommonConstants.TenantOwnersGroup.ToUpperInvariant());
        if (group == null)
        {
            logger.LogWarning(
                "The {Group} group does not exist; the first administrator keeps only the directly assigned roles",
                CommonConstants.TenantOwnersGroup);
            return;
        }

        var userId = adminUser.RtId.ToString();
        var members = await groupStore.GetMemberUserIdsAsync(group.RtId);
        if (members.Contains(userId, StringComparer.Ordinal))
        {
            return;
        }

        await groupStore.AddMemberUserAsync(group.RtId, userId);
    }

    private async Task TryAddRole(RtUser user, string roleName, bool required = true)
    {
        var rtRole = await roleManager.FindByNameAsync(roleName);
        if (rtRole == null)
        {
            if (!required)
            {
                return;
            }

            throw UserManagementException.RoleNotFound(roleName);
        }

        await userManager.AddToRoleAsync(user, rtRole.Name);
    }
}