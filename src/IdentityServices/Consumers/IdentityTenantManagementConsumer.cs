using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;

namespace Meshmakers.Octo.Backend.IdentityServices.Consumers;

/// <summary>
///     Consumer for <see cref="PreDeleteTenant" /> messages.
///     Cleans up <c>ClientMirror</c> tracking rows in the system tenant whenever a
///     child tenant is deleted. The mirror's actual <c>RtClient</c> record in the
///     child is gone with the tenant database, so no per-child cleanup is needed —
///     only the parent's tracking row would otherwise be left dangling.
/// </summary>
public class IdentityTenantManagementConsumer(
    ILogger<IdentityTenantManagementConsumer> logger,
    ISystemContext systemContext,
    IClientMirrorProvisioningService mirrorProvisioning) : IDistributedConsumer<PreDeleteTenant>
{
    public async Task ConsumeAsync(IDistributedContext<PreDeleteTenant> context)
    {
        var deletedTenantId = context.Message.TenantId;

        // Skip the system tenant itself — there is no parent above it whose tracking
        // rows would need cleaning, and the cleanup loop would just hit "tenant not
        // found" on every iteration once the system tenant is gone.
        if (string.Equals(deletedTenantId, systemContext.TenantId, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            // v1 assumption: the system tenant is the only parent that ever holds mirror
            // tracking rows. When nested customer sub-tenants land (see concept doc), this
            // needs to fan out across the ancestor chain.
            var removed = await mirrorProvisioning.RemoveMirrorsForChildTenantAsync(
                systemContext.TenantId, deletedTenantId);

            if (removed > 0)
            {
                logger.LogInformation(
                    "PreDeleteTenant cleanup: removed {Count} client mirror tracking row(s) for deleted tenant '{TenantId}'",
                    removed, deletedTenantId);
            }
        }
        catch (Exception ex)
        {
            // Cleanup failure must not break the broader tenant-delete cascade. The next
            // service restart's startup-time provisioning loop will not re-add these rows
            // (their child tenant no longer exists), so they are effectively orphan but
            // harmless until manually cleaned.
            logger.LogError(ex,
                "PreDeleteTenant cleanup failed for tenant '{TenantId}'", deletedTenantId);
        }
    }
}
