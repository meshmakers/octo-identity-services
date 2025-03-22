using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.Extensions.Logging;

namespace Meshmakers.Octo.Backend.Authentication.Consumers;

/// <summary>
///     Consumer for <see cref="CorsClientsUpdate" /> messages.
/// </summary>
public class IdentityProviderUpdateConsumer : IDistributedConsumer<IdentityProviderUpdate>
{
    private readonly IDynamicAuthSchemeService _authSchemeService;
    private readonly ILogger<IdentityProviderUpdateConsumer> _logger;

    /// <summary>
    ///     Constructor.
    /// </summary>
    /// <param name="logger"></param>
    /// <param name="authSchemeService"></param>
    public IdentityProviderUpdateConsumer(ILogger<IdentityProviderUpdateConsumer> logger, IDynamicAuthSchemeService authSchemeService)
    {
        _logger = logger;
        _authSchemeService = authSchemeService;
    }

    /// <inheritdoc />
    public async Task ConsumeAsync(IDistributedContext<IdentityProviderUpdate> context)
    {
        _logger.LogInformation("Cors client update for tenant received: {Text}", context.Message.TenantId);

        var tenantId = context.Message.TenantId.NormalizeString();

        await _authSchemeService.ConfigureAsync(tenantId);
    }
}