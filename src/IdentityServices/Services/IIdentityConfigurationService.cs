using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public interface IIdentityConfigurationService : ITenantConfigurationService
{
    Task<RtMailNotificationConfiguration> GetMailNotificationConfigurationAsync(string tenantId);
}