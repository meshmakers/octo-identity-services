using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <remarks>
/// Grants are always stored in the system tenant database regardless of the current HTTP tenant context.
/// This avoids mismatches between the <c>/connect/authorize</c> endpoint (which resolves tenant from
/// <c>acr_values</c>) and the <c>/connect/token</c> endpoint (which has no tenant context), ensuring
/// the authorization code can always be found during the token exchange.
/// </remarks>
public class PersistentGrantStore(ISystemContext systemContext, IMapper mapper)
    : IOctoPersistentGrantStore
{
    private const int TokenCleanupBatchSize = 50;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private readonly ITenantRepository _tenantRepository = systemContext.GetSystemTenantRepository();

    public async Task StoreAsync(PersistedGrant grant)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var persistedGrant = await GetRtPersistentGrantByKeyAsync(session, grant.Key);
        if (persistedGrant == null)
        {
            var appGrant = GetApplicationPersistedGrant(grant);

            await _tenantRepository.InsertOneRtEntityAsync(session, appGrant);
        }
        else
        {
            var appGrant = GetApplicationPersistedGrant(grant);

            await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, persistedGrant.RtId, appGrant);
        }

        await session.CommitTransactionAsync();
    }

    public async Task<PersistedGrant?> GetAsync(string key)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await GetAsync(session, key);

        await session.CommitTransactionAsync();
        return result;
    }


    public async Task<IEnumerable<PersistedGrant>> GetAllAsync(PersistedGrantFilter filter)
    {
        var session = await _tenantRepository.GetSessionAsync();
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

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session,
            queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.Select(mapper.Map<PersistedGrant>);
    }

    public async Task RemoveAsync(string key)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And)
            .Field(nameof(RtPersistedGrant.GrantKey), FieldFilterOperator.Equals, key);

        await _tenantRepository.DeleteOneRtEntityAsync<RtPersistedGrant>(session, fieldFilterCriteria, DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAllAsync(PersistedGrantFilter filter)
    {
        var session = await _tenantRepository.GetSessionAsync();
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
        await _tenantRepository.DeleteManyRtEntitiesAsync<RtPersistedGrant>(session, fieldFilterCriteria, DeleteOptions.Erase);

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

            var session = await _tenantRepository.GetSessionAsync();
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
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var persistedGrant = await GetRtPersistentGrantByKeyAsync(session, grant.GrantKey);
        if (persistedGrant == null)
        {
            await _tenantRepository.InsertOneRtEntityAsync(session, grant);
        }
        else
        {
            await _tenantRepository.ReplaceOneRtEntityByIdAsync(session, persistedGrant.RtId, grant);
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

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And)
            .FieldEquals(nameof(RtPersistedGrant.SubjectId), subjectId)
            .FieldEquals(nameof(RtPersistedGrant.ClientId), clientId)
            .FieldEquals(nameof(RtPersistedGrant.GrantType), type);

        await _tenantRepository.DeleteManyRtEntitiesAsync<RtPersistedGrant>(session, fieldFilterCriteria, DeleteOptions.Erase);

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

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session, queryOptions);
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
            var query = await _tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session,
                queryOptions,
                0, TokenCleanupBatchSize);
            var expiredGrants = query.Items.OrderBy(x => x.GrantKey)
                .ToList();

            found = expiredGrants.Count;
            Logger.Info($"Removing {found} grants");

            if (found > 0)
            {
                try
                {
                    foreach (var persistedGrant in expiredGrants)
                    {
                        await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(session, persistedGrant.RtId, DeleteOptions.Erase);
                    }
                }
                catch (OperationFailedException ex)
                {
                    // we get this if/when someone else already deleted the records
                    // we want to essentially ignore this, and keep working
                    Logger.Debug($"Concurrency exception removing expired grants: {ex.Message}");
                }
            }
        }
    }
}