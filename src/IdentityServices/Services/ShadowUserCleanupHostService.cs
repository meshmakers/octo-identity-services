using IdentityServerPersistence.Services.ShadowUserCleanup;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Runs <see cref="IShadowUserCleanupJob" /> once per process start when
///     <c>IdentityApiAuthorization:ShadowUserCleanup</c> is DryRun or Apply (AB#8305). Off returns at once and reads
///     nothing. The run starts <see cref="StartDelay" /> after the application has started, so the start-up tenant
///     setup is done first, and it runs in the background: it never blocks or fails the identity start-up.
/// </summary>
internal sealed class ShadowUserCleanupHostService(
    IServiceScopeFactory scopeFactory,
    IOptions<ShadowUserCleanupOptions> options,
    IHostApplicationLifetime lifetime,
    ILogger<ShadowUserCleanupHostService> logger) : BackgroundService
{
    /// <summary>Wait after the application has started before the run.</summary>
    internal static readonly TimeSpan StartDelay = TimeSpan.FromMinutes(2);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var mode = options.Value.ShadowUserCleanup;
        if (mode == ShadowUserCleanupMode.Off)
        {
            return;
        }

        try
        {
            await WaitForStartedAsync(stoppingToken);
            await Task.Delay(StartDelay, stoppingToken);
            logger.LogInformation("ShadowUserCleanup {Mode} starting", mode);
            using var scope = scopeFactory.CreateScope();
            await scope.ServiceProvider.GetRequiredService<IShadowUserCleanupJob>().RunOnceAsync(mode, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutdown.
        }
        catch (Exception ex)
        {
            // Never take the host down: the next start runs again.
            logger.LogError(ex, "ShadowUserCleanup {Mode} failed", mode);
        }
    }

    private Task WaitForStartedAsync(CancellationToken stoppingToken)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lifetime.ApplicationStarted.Register(() => started.TrySetResult());
        stoppingToken.Register(() => started.TrySetCanceled(stoppingToken));
        return started.Task;
    }
}
