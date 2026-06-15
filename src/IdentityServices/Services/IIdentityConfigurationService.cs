using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public interface IIdentityConfigurationService : ITenantConfigurationService
{
    Task<RtMailNotificationConfiguration> GetMailNotificationConfigurationAsync(string tenantId);
}