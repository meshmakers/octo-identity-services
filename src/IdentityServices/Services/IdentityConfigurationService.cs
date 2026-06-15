using IdentityServerPersistence;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

// ReSharper disable once ClassNeverInstantiated.Global
public class IdentityConfigurationService(ISystemContext systemContext)
    : DefaultTenantConfigurationService(systemContext), IIdentityConfigurationService
{

    public Task<RtMailNotificationConfiguration> GetMailNotificationConfigurationAsync(string tenantId)
    {
        return GetOrRetrieveConfiguration<RtMailNotificationConfiguration>(tenantId,
            IdentityServiceConstants.MailNotificationConfigurationName);
    }
}