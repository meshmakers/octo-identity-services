using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Messages;
using Microsoft.Extensions.Logging;

namespace Meshmakers.Octo.Backend.Authentication.Consumers;

/// <summary>
/// Consumer for <see cref="CorsClientsUpdate"/> messages.
/// </summary>
public class IdentityProviderUpdateConsumer : IDistributedConsumer<IdentityProviderUpdate>
{
    // TODO: This consumer needs to be configured by AddConsumer<T> in the service collection.
    readonly ILogger<IdentityProviderUpdateConsumer> _logger;
    private readonly IDynamicAuthSchemeService _authSchemeService;

    /// <summary>
    /// Constructor.
    /// </summary>
    /// <param name="logger"></param>
    /// <param name="authSchemeService"></param>
    public IdentityProviderUpdateConsumer(ILogger<IdentityProviderUpdateConsumer> logger, IDynamicAuthSchemeService authSchemeService)
    {
        _logger = logger;
        _authSchemeService = authSchemeService;
    }

    /// <inheritdoc />
    public Task ConsumeAsync(IDistributedContext<IdentityProviderUpdate> context)
    {
        _logger.LogInformation("Cors client update for tenant received: {Text}", context.Message.TenantId);

        var key = context.Message.TenantId?.NormalizeString();

        _authSchemeService.ConfigureAsync(key);

        return Task.CompletedTask;
    }
}