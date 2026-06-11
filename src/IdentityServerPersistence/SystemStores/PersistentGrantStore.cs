using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
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
    IMultiTenancyResolverService multiTenancyResolverService,
    IMapper mapper)
    : IOctoPersistentGrantStore
{
    private const int TokenCleanupBatchSize = 50;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async Task StoreAsync(PersistedGrant grant, CancellationToken cancellationToken = default)
    {
        await MongoWriteRetry.ExecuteWithRetryAsync(() => StoreInternalAsync(grant));
    }

    private async Task StoreInternalAsync(PersistedGrant grant)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var persistedGrant = await GetRtPersistentGrantByKeyAsync(session, grant.Key);
        if (persistedGrant == null)
        {
            var appGrant = GetApplicationPersistedGrant(grant);

            await TenantRepository.InsertOneRtEntityAsync(session, appGrant);
        }
        else
        {
            var appGrant = GetApplicationPersistedGrant(grant);

            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, persistedGrant.RtId, appGrant);
        }

        await session.CommitTransactionAsync();
    }

    public async Task<PersistedGrant?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await GetAsync(session, key);

        await session.CommitTransactionAsync();
        return result;
    }


    public async Task<IReadOnlyCollection<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create();
        if (filter.SubjectId != null)
        {
            queryOptions.FieldFilter(nameof(RtPersistedGrant.SubjectId), FieldFilterOperator.Equals, filter.SubjectId);
        }
        if (filter.SessionId != null)
        {
            queryOptions.FieldFilter(nameof(RtPersistedGrant.SessionId), FieldFilterOperator.Equals, filter.SessionId);
        }
        if (filter.ClientId != null)
        {
            queryOptions.FieldFilter(nameof(RtPersistedGrant.ClientId), FieldFilterOperator.Equals, filter.ClientId);
        }
        if (filter.Type != null)
        {
            queryOptions.FieldFilter(nameof(RtPersistedGrant.GrantType), FieldFilterOperator.Equals, filter.Type);
        }

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session,
            queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.Select(mapper.Map<PersistedGrant>).ToList();
    }

    public async Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And)
            .Field(nameof(RtPersistedGrant.GrantKey), FieldFilterOperator.Equals, key);

        await TenantRepository.DeleteOneRtEntityAsync<RtPersistedGrant>(session, fieldFilterCriteria, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAllAsync(PersistedGrantFilter filter, CancellationToken cancellationToken = default)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And);
        if (!string.IsNullOrWhiteSpace(filter.SubjectId))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtPersistedGrant.SubjectId), filter.SubjectId);
        }
        if (!string.IsNullOrWhiteSpace(filter.SessionId))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtPersistedGrant.SessionId), filter.SessionId);
        }
        if (!string.IsNullOrWhiteSpace(filter.ClientId))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtPersistedGrant.ClientId), filter.ClientId);
        }
        if (!string.IsNullOrWhiteSpace(filter.Type))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtPersistedGrant.GrantType), filter.Type);
        }
        await TenantRepository.DeleteManyRtEntitiesAsync<RtPersistedGrant>(session, fieldFilterCriteria, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

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

    private RtPersistedGrant GetApplicationPersistedGrant(PersistedGrant grant)
    {
        return mapper.Map<RtPersistedGrant>(grant);
    }

    public async Task RemoveAllAsync(string subjectId, string clientId, string type)
    {
        ArgumentValidation.ValidateString(nameof(subjectId), subjectId);
        ArgumentValidation.ValidateString(nameof(clientId), clientId);
        ArgumentValidation.ValidateString(nameof(type), type);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And)
            .FieldEquals(nameof(RtPersistedGrant.SubjectId), subjectId)
            .FieldEquals(nameof(RtPersistedGrant.ClientId), clientId)
            .FieldEquals(nameof(RtPersistedGrant.GrantType), type);

        await TenantRepository.DeleteManyRtEntitiesAsync<RtPersistedGrant>(session, fieldFilterCriteria, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    private async Task<PersistedGrant?> GetAsync(IOctoSession session, string key)
    {
        var rtPersistentGrant = await GetRtPersistentGrantByKeyAsync(session, key);
        return mapper.Map<PersistedGrant>(rtPersistentGrant);
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