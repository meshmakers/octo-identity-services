using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

// ReSharper disable once ClassNeverInstantiated.Global
public class IdentityConfigurationService(ISystemContext systemContext)
    : DefaultTenantConfigurationService(systemContext), IIdentityConfigurationService
{
    private const string MailNotificationConfigurationName = "MailNotificationConfiguration";

    public Task<RtMailNotificationConfiguration> GetMailNotificationConfigurationAsync(string tenantId)
    {
        return GetOrRetrieveConfiguration(tenantId, MailNotificationConfigurationName,
            new RtMailNotificationConfiguration
            {
                RtWellKnownName = MailNotificationConfigurationName,
                EnableEmailNotifications = false
            });
    }
}