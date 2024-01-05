using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Microsoft.Extensions.Options;
using NLog;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

internal class TokenCleanupHostService : IHostedService
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
    private readonly IOptions<OctoIdentityServicesOptions> _identityOptions;
    private readonly IServiceProvider _serviceProvider;

    private CancellationTokenSource? _source;

    public TokenCleanupHostService(IServiceProvider serviceProvider,
        IOptions<OctoIdentityServicesOptions> identityOptions)
    {
        _serviceProvider = serviceProvider;
        _identityOptions = identityOptions;
    }

    private TimeSpan CleanupInterval => TimeSpan.FromSeconds(_identityOptions.Value.TokenCleanupInterval);

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_identityOptions.Value.EnableTokenCleanup)
        {
            if (_source != null)
            {
                throw new InvalidOperationException("Already started. Call Stop first.");
            }

            Logger.Debug("Starting grant removal");

            _source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            Task.Factory.StartNew(() => StartInternalAsync(_source.Token), cancellationToken);
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (_identityOptions.Value.EnableTokenCleanup)
        {
            if (_source == null)
                // Nothing was initialized, so exit.
            {
                return Task.CompletedTask;
            }

            Logger.Debug("Stopping grant removal");

            _source.Cancel();
            _source = null;
        }

        return Task.CompletedTask;
    }

    private async Task StartInternalAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                Logger.Debug("CancellationRequested. Exiting.");
                break;
            }

            try
            {
                await Task.Delay(CleanupInterval, cancellationToken);
            }
            catch (TaskCanceledException)
            {
                Logger.Debug("TaskCanceledException. Exiting.");
                break;
            }
            catch (Exception ex)
            {
                Logger.Error("Task.Delay exception: {Message}. Exiting", ex.Message);
                break;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                Logger.Debug("CancellationRequested. Exiting.");
                break;
            }

            await RemoveExpiredGrantsAsync();
        }
    }

    private async Task RemoveExpiredGrantsAsync()
    {
        try
        {
            using (var serviceScope = _serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var persistentGrantStore = serviceScope.ServiceProvider.GetRequiredService<IOctoPersistentGrantStore>();
                await persistentGrantStore.RemoveExpiredGrantsAsync();
            }
        }
        catch (Exception ex)
        {
            Logger.Error("Exception removing expired grants: {Message}", ex.Message);
        }
    }
}