using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace IdentityServerPersistence.SystemStores;

public class PersistentGrantStore : IOctoPersistentGrantStore
{
    private const int TokenCleanupBatchSize = 50;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
    private readonly IMapper _mapper;

    private readonly ITenantRepository _tenantRepository;

    public PersistentGrantStore(IMultiTenancyResolverService multiTenancyResolverService, IMapper mapper)
    {
        _tenantRepository = multiTenancyResolverService.GetTenantRepository();
        _mapper = mapper;
    }

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

        var dataQueryOperation = DataQueryOperation.Create();
        if(filter.SubjectId != null)
        {
            dataQueryOperation.FieldFilter(nameof(RtPersistedGrant.SubjectId), FieldFilterOperator.Equals, filter.SubjectId);
        }
        if(filter.SessionId != null)
        {
            dataQueryOperation.FieldFilter(nameof(RtPersistedGrant.SessionId), FieldFilterOperator.Equals, filter.SessionId);
        }
        if(filter.SessionId != null)
        {
            dataQueryOperation.FieldFilter(nameof(RtPersistedGrant.ClientId), FieldFilterOperator.Equals, filter.ClientId);
        }
        if(filter.Type != null)
        {
            dataQueryOperation.FieldFilter(nameof(RtPersistedGrant.GrantType), FieldFilterOperator.Equals, filter.Type);
        }

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session,
            dataQueryOperation);

        await session.CommitTransactionAsync();
        return result.Items.Select(_mapper.Map<PersistedGrant>);
    }

    public async Task RemoveAsync(string key)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilters = new List<FieldFilter>
        {
            new(nameof(RtPersistedGrant.GrantKey), FieldFilterOperator.Equals, key)
        };
        await _tenantRepository.DeleteOneRtEntityAsync<RtPersistedGrant>(session, fieldFilters);

        await session.CommitTransactionAsync();
    }

    public async Task RemoveAllAsync(PersistedGrantFilter filter)
    {
        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilters = new List<FieldFilter>();
        if (!string.IsNullOrWhiteSpace(filter.SubjectId))
        {
            fieldFilters.Add(new(nameof(RtPersistedGrant.SubjectId), FieldFilterOperator.Equals, filter.SubjectId));
        }
        if (!string.IsNullOrWhiteSpace(filter.SessionId))
        {
            fieldFilters.Add(new(nameof(RtPersistedGrant.SessionId), FieldFilterOperator.Equals, filter.SessionId));
        }
        if (!string.IsNullOrWhiteSpace(filter.ClientId))
        {
            fieldFilters.Add(new(nameof(RtPersistedGrant.ClientId), FieldFilterOperator.Equals, filter.ClientId));
        }
        if (!string.IsNullOrWhiteSpace(filter.Type))
        {
            fieldFilters.Add(new(nameof(RtPersistedGrant.GrantType), FieldFilterOperator.Equals, filter.Type));
        }
        await _tenantRepository.DeleteOneRtEntityAsync<RtPersistedGrant>(session, fieldFilters);

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
        return _mapper.Map<RtPersistedGrant>(grant);
    }

    public async Task RemoveAllAsync(string subjectId, string clientId, string type)
    {
        ArgumentValidation.ValidateString(nameof(subjectId), subjectId);
        ArgumentValidation.ValidateString(nameof(clientId), clientId);
        ArgumentValidation.ValidateString(nameof(type), type);

        var session = await _tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilters = new List<FieldFilter>
        {
            new(nameof(RtPersistedGrant.SubjectId), FieldFilterOperator.Equals, subjectId),
            new(nameof(RtPersistedGrant.ClientId), FieldFilterOperator.Equals, clientId),
            new(nameof(RtPersistedGrant.GrantType), FieldFilterOperator.Equals, type)
        };
        await _tenantRepository.DeleteManyRtEntitiesAsync<RtPersistedGrant>(session, fieldFilters);

        await session.CommitTransactionAsync();
    }

    private async Task<PersistedGrant?> GetAsync(IOctoSession session, string key)
    {
        var rtPersistentGrant = await GetRtPersistentGrantByKeyAsync(session, key);
        return _mapper.Map<PersistedGrant>(rtPersistentGrant);
    }

    private async Task<RtPersistedGrant?> GetRtPersistentGrantByKeyAsync(IOctoSession session, string key)
    {
        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtPersistedGrant.GrantKey), FieldFilterOperator.Equals, key);

        var result = await _tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session, dataQueryOperation);
        return result.Items.FirstOrDefault();
    }

    /// <summary>
    ///     Removes the stale persisted grants.
    /// </summary>
    /// <returns></returns>
    private async Task RemoveGrantsAsync(IOctoSession session)
    {
        var found = int.MaxValue;

        var dataQueryOperation = DataQueryOperation.Create()
            .FieldFilter(nameof(RtPersistedGrant.ExpirationDateTime), FieldFilterOperator.LessEqualThan, DateTime.UtcNow);

        while (found >= TokenCleanupBatchSize)
        {
            var query = await _tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session,
                dataQueryOperation,
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
                        await _tenantRepository.DeleteOneRtEntityByRtIdAsync<RtPersistedGrant>(session, persistedGrant.RtId);
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