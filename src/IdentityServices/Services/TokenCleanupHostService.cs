using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
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

            // AB#4338: erase expired dynamically-registered clients (RFC 7591) + their mirrors.
            // They live in the system tenant; removing mirrors cleans the child-tenant copies too.
            await RemoveExpiredDynamicClientsAsync(serviceScope, systemContext);

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

    private static async Task RemoveExpiredDynamicClientsAsync(IServiceScope scope, ISystemContext systemContext)
    {
        try
        {
            var systemRepo = systemContext.GetSystemTenantRepository();
            var mirrorService = scope.ServiceProvider.GetRequiredService<IClientMirrorProvisioningService>();

            List<RtClient> expired;
            using (var session = await systemRepo.GetSessionAsync())
            {
                session.StartTransaction();
                var query = await systemRepo.GetRtEntitiesByTypeAsync<RtClient>(session,
                    RtEntityQueryOptions.Create()
                        .FieldFilter(nameof(RtClient.DynamicRegistration), FieldFilterOperator.Equals, true));
                var now = DateTime.UtcNow;
                expired = query.Items
                    .Where(c => c.DynamicRegistrationExpiresAt.HasValue &&
                                c.DynamicRegistrationExpiresAt.Value <= now)
                    .ToList();
                await session.CommitTransactionAsync();
            }

            if (expired.Count == 0)
            {
                return;
            }

            Logger.Info("Removing {Count} expired dynamic client(s) from tenant '{TenantId}'",
                expired.Count, systemRepo.TenantId);

            foreach (var client in expired)
            {
                try
                {
                    // Remove child-tenant mirrors + parent tracking rows first, then the system client.
                    await mirrorService.RemoveMirrorsForClientAsync(systemRepo.TenantId, client.ClientId);

                    using var session = await systemRepo.GetSessionAsync();
                    session.StartTransaction();
                    await systemRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(session, client.RtId, DeleteOptions.Erase);
                    await session.CommitTransactionAsync();
                }
                catch (Exception ex)
                {
                    Logger.Error("Exception removing expired dynamic client '{ClientId}': {Message}",
                        client.ClientId, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Error("Exception removing expired dynamic clients: {Message}", ex.Message);
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

            using var session = await tenantRepository.GetSessionAsync();
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

                    var deletedCount = 0;
                    foreach (var persistedGrant in expiredGrants)
                    {
                        try
                        {
                            await tenantRepository.DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(session,
                                persistedGrant.RtId, DeleteOptions.Erase);
                            deletedCount++;
                        }
                        catch (OperationFailedException ex)
                        {
                            Logger.Debug(
                                "Concurrency exception removing expired grant '{RtId}' for tenant '{TenantId}': {Message}",
                                persistedGrant.RtId, tenantRepository.TenantId, ex.Message);
                        }
                    }

                    if (deletedCount == 0)
                    {
                        Logger.Warn(
                            "Stopping expired grant cleanup for tenant '{TenantId}' because no grants could be deleted from the current batch due to concurrency conflicts",
                            tenantRepository.TenantId);
                        break;
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
