using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Options;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

internal class TokenCleanupHostService : IHostedService
{
    private const int TokenCleanupBatchSize = 50;

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
            using var serviceScope = _serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();
            var systemContext = serviceScope.ServiceProvider.GetRequiredService<ISystemContext>();

            // Clean up grants in the system tenant
            await RemoveExpiredGrantsForTenantAsync(systemContext.GetSystemTenantRepository());

            // Clean up grants in all child tenants
            if (!await systemContext.IsSystemTenantExistingAsync())
            {
                return;
            }

            List<OctoTenant> tenantList;
            using (var adminSession = await systemContext.GetAdminSessionAsync())
            {
                adminSession.StartTransaction();
                var tenants = await systemContext.GetChildTenantsAsync(adminSession);
                tenantList = tenants.Items.ToList();
                await adminSession.CommitTransactionAsync();
            }

            foreach (var tenant in tenantList)
            {
                try
                {
                    var tenantRepo = await systemContext.TryFindTenantRepositoryAsync(tenant.TenantId);
                    if (tenantRepo != null)
                    {
                        await RemoveExpiredGrantsForTenantAsync(tenantRepo);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error("Exception removing expired grants for tenant '{TenantId}': {Message}",
                        tenant.TenantId, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Error("Exception removing expired grants: {Message}", ex.Message);
        }
    }

    private static async Task RemoveExpiredGrantsForTenantAsync(ITenantRepository tenantRepository)
    {
        try
        {
            var found = int.MaxValue;

            var queryOptions = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtPersistedGrant.ExpirationDateTime), FieldFilterOperator.LessEqualThan,
                    DateTime.UtcNow);

            var session = await tenantRepository.GetSessionAsync();
            session.StartTransaction();

            while (found >= TokenCleanupBatchSize)
            {
                var query = await tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session,
                    queryOptions, 0, TokenCleanupBatchSize);
                var expiredGrants = query.Items.OrderBy(x => x.GrantKey).ToList();

                found = expiredGrants.Count;
                if (found > 0)
                {
                    Logger.Info("Removing {Count} expired grants from tenant '{TenantId}'",
                        found, tenantRepository.TenantId);

                    try
                    {
                        foreach (var persistedGrant in expiredGrants)
                        {
                            await tenantRepository.DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(session,
                                persistedGrant.RtId, DeleteOptions.Erase);
                        }
                    }
                    catch (OperationFailedException ex)
                    {
                        Logger.Debug("Concurrency exception removing expired grants: {Message}", ex.Message);
                    }
                }
            }

            await session.CommitTransactionAsync();
        }
        catch (Exception ex)
        {
            Logger.Error("Exception removing expired grants for tenant '{TenantId}': {Message}",
                tenantRepository.TenantId, ex.Message);
        }
    }
}
