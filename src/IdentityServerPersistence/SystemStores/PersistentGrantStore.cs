using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <remarks>
/// Grants are stored in the per-tenant database resolved from the current HTTP context.
/// The <see cref="IMultiTenancyResolverService"/> determines the correct tenant repository,
/// which is set by <c>OidcTenantResolutionMiddleware</c> before IdentityServer processes
/// the request. This ensures proper data isolation per tenant.
/// </remarks>
public class PersistentGrantStore(
    IMultiTenancyResolverService multiTenancyResolverService)
    : IOctoPersistentGrantStore
{
    private const int TokenCleanupBatchSize = 50;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    /// <summary>
    ///     Method to clear expired persisted grants.
    /// </summary>
    /// <returns></returns>
    public async Task RemoveExpiredGrantsAsync()
    {
        try
        {
            Logger.Trace("Querying for expired grants to remove");

            var session = await TenantRepository.GetSessionAsync();
            session.StartTransaction();

            await RemoveGrantsAsync(session);

            await session.CommitTransactionAsync();
        }
        catch (Exception ex)
        {
            Logger.Error("Exception removing expired grants: {Exception}", ex.Message);
        }
    }

    public async Task StoreAsync(RtPersistedGrant grant)
    {
        await MongoWriteRetry.ExecuteWithRetryAsync(() => StoreRtGrantInternalAsync(grant));
    }

    private async Task StoreRtGrantInternalAsync(RtPersistedGrant grant)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var persistedGrant = await GetRtPersistentGrantByKeyAsync(session, grant.GrantKey);
        if (persistedGrant == null)
        {
            await TenantRepository.InsertOneRtEntityAsync(session, grant);
        }
        else
        {
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, persistedGrant.RtId, grant);
        }

        await session.CommitTransactionAsync();
    }

    private async Task<RtPersistedGrant?> GetRtPersistentGrantByKeyAsync(IOctoSession session, string key)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtPersistedGrant.GrantKey), FieldFilterOperator.Equals, key);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session, queryOptions);
        return result.Items.FirstOrDefault();
    }

    /// <summary>
    ///     Removes the stale persisted grants.
    /// </summary>
    /// <returns></returns>
    private async Task RemoveGrantsAsync(IOctoSession session)
    {
        var found = int.MaxValue;

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtPersistedGrant.ExpirationDateTime), FieldFilterOperator.LessEqualThan, DateTime.UtcNow);

        while (found >= TokenCleanupBatchSize)
        {
            var query = await TenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session,
                queryOptions,
                0, TokenCleanupBatchSize);
            var expiredGrants = query.Items.OrderBy(x => x.GrantKey)
                .ToList();

            found = expiredGrants.Count;
            Logger.Info($"Removing {found} grants");

            if (found > 0)
            {
                var deletedCount = 0;
                foreach (var persistedGrant in expiredGrants)
                {
                    try
                    {
                        await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(session, persistedGrant.RtId, DeleteOptions.Erase);
                        deletedCount++;
                    }
                    catch (OperationFailedException ex)
                    {
                        Logger.Debug("Concurrency exception removing expired grant '{RtId}': {Message}",
                            persistedGrant.RtId, ex.Message);
                    }
                }

                if (deletedCount == 0)
                {
                    Logger.Warn("Stopping expired grant cleanup because no grants could be deleted from the current batch due to concurrency conflicts");
                    break;
                }
            }
        }
    }
}