using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Runs <see cref="IClientMirrorReconciliationJob" /> every <c>Identity:ClientMirrorReconciliationInterval</c>
///     seconds (AB#8019; default 300, 0 or less = off). The first pass runs one interval after start: the start-up
///     provisioning already re-converges the mirrors of every tenant. A small random offset per replica spreads the
///     passes of several replicas; correctness does not depend on it (the pass is idempotent and version-checked).
/// </summary>
internal sealed class ClientMirrorReconciliationHostService(
    IServiceScopeFactory scopeFactory,
    IOptions<OctoIdentityServicesOptions> options,
    ILogger<ClientMirrorReconciliationHostService> logger) : BackgroundService
{
    /// <summary>The interval, or <c>null</c> when the job is switched off.</summary>
    internal static TimeSpan? GetInterval(OctoIdentityServicesOptions options) =>
        options.ClientMirrorReconciliationInterval > 0
            ? TimeSpan.FromSeconds(options.ClientMirrorReconciliationInterval)
            : null;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = GetInterval(options.Value);
        if (interval == null)
        {
            logger.LogInformation("Client mirror reconciliation is switched off (Identity:ClientMirrorReconciliationInterval <= 0)");
            return;
        }

        var jitter = TimeSpan.FromMilliseconds(Random.Shared.NextDouble() *
                                               Math.Min(interval.Value.TotalMilliseconds / 10, 30_000));
        try
        {
            await Task.Delay(interval.Value + jitter, stoppingToken);
            using var timer = new PeriodicTimer(interval.Value);
            do
            {
                await RunPassAsync(stoppingToken);
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutdown.
        }
    }

    private async Task RunPassAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            await scope.ServiceProvider.GetRequiredService<IClientMirrorReconciliationJob>().RunOnceAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Never end the loop: the next pass retries.
            logger.LogError(ex, "Client mirror reconciliation pass failed");
        }
    }
}
