using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public interface IUserManagementService
{
    Task CreateAdminUserAsync(AdminUserDto adminUserDto);
}