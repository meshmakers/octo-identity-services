using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;

namespace Meshmakers.Octo.Backend.IdentityServices.Consumers;

/// <summary>
///     Consumer for <see cref="CorsClientsUpdate" /> messages.
///     Invalidates the Identity CORS policy cache when client CORS origins change.
/// </summary>
public class IdentityCorsClientsUpdateConsumer(
    ILogger<IdentityCorsClientsUpdateConsumer> logger,
    IdentityCorsPolicyProvider corsPolicyProvider) : IDistributedConsumer<CorsClientsUpdate>
{
    public Task ConsumeAsync(IDistributedContext<CorsClientsUpdate> context)
    {
        logger.LogInformation("CORS client update for tenant received: {TenantId}", context.Message.TenantId);

        corsPolicyProvider.InvalidateCache();

        return Task.CompletedTask;
    }
}
