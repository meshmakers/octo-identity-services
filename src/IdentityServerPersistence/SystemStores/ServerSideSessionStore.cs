using AutoMapper;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NLog;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     Duende server-side session store backed by the CK runtime (MongoDB).
/// </summary>
/// <remarks>
///     Sessions are stored in the per-tenant database resolved from the current HTTP context
///     (same pattern as <see cref="PersistentGrantStore" />): the per-tenant auth cookie
///     (<c>TenantCookieManager</c>) is only presented on requests that run in that tenant's
///     context, so reads and writes naturally hit the right database.
///     The expired-session sweep (<see cref="GetAndRemoveExpiredSessionsAsync" />) is invoked by
///     Duende's background cleanup WITHOUT an HTTP context, so it iterates the system tenant and
///     all child tenants via <see cref="ISystemContext" /> (same pattern as
///     <c>TokenCleanupHostService</c>).
/// </remarks>
public class ServerSideSessionStore(
    IMultiTenancyResolverService multiTenancyResolverService,
    ISystemContext systemContext,
    IMapper mapper)
    : IServerSideSessionStore
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async Task<ServerSideSession?> GetSessionAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var rtSession = await GetRtSessionByKeyAsync(TenantRepository, session, key);
        await session.CommitTransactionAsync();

        if (rtSession == null)
        {
            return null;
        }

        // Expired-but-not-yet-cleaned sessions must not authenticate. The periodic cleanup
        // (GetAndRemoveExpiredSessionsAsync) is garbage collection, not the authority.
        if (rtSession.ExpirationDateTime.HasValue && rtSession.ExpirationDateTime.Value <= DateTime.UtcNow)
        {
            return null;
        }

        return mapper.Map<ServerSideSession>(rtSession);
    }

    public async Task CreateSessionAsync(ServerSideSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        await MongoWriteRetry.ExecuteWithRetryAsync(() => CreateSessionInternalAsync(session));
    }

    private async Task CreateSessionInternalAsync(ServerSideSession session)
    {
        var rtSession = mapper.Map<RtServerSideSession>(session);
        rtSession.RtId = OctoObjectId.GenerateNewId();

        using var octoSession = await TenantRepository.GetSessionAsync();
        octoSession.StartTransaction();
        await TenantRepository.InsertOneRtEntityAsync(octoSession, rtSession);
        await octoSession.CommitTransactionAsync();
    }

    public async Task UpdateSessionAsync(ServerSideSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        await MongoWriteRetry.ExecuteWithRetryAsync(() => UpdateSessionInternalAsync(session));
    }

    private async Task UpdateSessionInternalAsync(ServerSideSession session)
    {
        using var octoSession = await TenantRepository.GetSessionAsync();
        octoSession.StartTransaction();

        var existing = await GetRtSessionByKeyAsync(TenantRepository, octoSession, session.Key);
        if (existing == null)
        {
            // Renewal of a session that was cleaned up concurrently — recreate it.
            var inserted = mapper.Map<RtServerSideSession>(session);
            inserted.RtId = OctoObjectId.GenerateNewId();
            await TenantRepository.InsertOneRtEntityAsync(octoSession, inserted);
        }
        else
        {
            var replacement = mapper.Map<RtServerSideSession>(session);
            await TenantRepository.ReplaceOneRtEntityByIdAsync(octoSession, existing.RtId, replacement);
        }

        await octoSession.CommitTransactionAsync();
    }

    public async Task DeleteSessionAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentValidation.ValidateString(nameof(key), key);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And)
            .FieldEquals(nameof(RtServerSideSession.SessionKey), key);

        await TenantRepository.DeleteOneRtEntityAsync<RtServerSideSession>(session, fieldFilterCriteria,
            DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task<IReadOnlyCollection<ServerSideSession>> GetSessionsAsync(SessionFilter filter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        filter.Validate();

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = CreateFilterQueryOptions(filter.SubjectId, filter.SessionId);
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session, queryOptions);

        await session.CommitTransactionAsync();
        return result.Items.Select(mapper.Map<ServerSideSession>).ToList();
    }

    public async Task DeleteSessionsAsync(SessionFilter filter, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        filter.Validate();

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var fieldFilterCriteria = FieldFilterCriteria.Create(LogicalOperators.And);
        if (!string.IsNullOrWhiteSpace(filter.SubjectId))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtServerSideSession.SubjectId), filter.SubjectId);
        }
        if (!string.IsNullOrWhiteSpace(filter.SessionId))
        {
            fieldFilterCriteria.FieldEquals(nameof(RtServerSideSession.SessionId), filter.SessionId);
        }

        await TenantRepository.DeleteManyRtEntitiesAsync<RtServerSideSession>(session, fieldFilterCriteria,
            DeleteOptions.Erase);

        await session.CommitTransactionAsync();
    }

    public async Task<IReadOnlyCollection<ServerSideSession>> GetAndRemoveExpiredSessionsAsync(int count,
        CancellationToken cancellationToken = default)
    {
        // Invoked by Duende's background cleanup host — NO HTTP context, so the per-request
        // tenant resolver cannot be used. Sweep the system tenant first, then all child tenants
        // (same pattern as TokenCleanupHostService).
        var removed = new List<ServerSideSession>();

        try
        {
            await CollectExpiredSessionsForTenantAsync(systemContext.GetSystemTenantRepository(), removed, count);

            if (removed.Count >= count || !await systemContext.IsSystemTenantExistingAsync())
            {
                return removed;
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
                if (cancellationToken.IsCancellationRequested) { break; }

                if (removed.Count >= count)
                {
                    break;
                }

                try
                {
                    var tenantRepo = await systemContext.TryFindTenantRepositoryAsync(tenant.TenantId);
                    if (tenantRepo != null)
                    {
                        await CollectExpiredSessionsForTenantAsync(tenantRepo, removed, count);
                    }
                }
                catch (Exception ex)
                {
                    Logger.Error("Exception removing expired sessions for tenant '{TenantId}': {Message}",
                        tenant.TenantId, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Error("Exception removing expired sessions: {Message}", ex.Message);
        }

        return removed;
    }

    public async Task<QueryResult<ServerSideSession>> QuerySessionsAsync(SessionQuery? filter = null,
        CancellationToken cancellationToken = default)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = CreateFilterQueryOptions(filter?.SubjectId, filter?.SessionId);
        if (!string.IsNullOrWhiteSpace(filter?.DisplayName))
        {
            queryOptions.FieldFilter(nameof(RtServerSideSession.DisplayName), FieldFilterOperator.Like,
                filter.DisplayName);
        }

        var take = filter is { CountRequested: > 0 } ? filter.CountRequested : 25;
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session,
            queryOptions, 0, take);

        await session.CommitTransactionAsync();

        var items = result.Items.Select(mapper.Map<ServerSideSession>).ToList();
        return new QueryResult<ServerSideSession>
        {
            Results = items,
            // Single-page result: no continuation token support (admin/diagnostic surface only).
            ResultsToken = string.Empty,
            HasPrevResults = false,
            HasNextResults = false,
            TotalCount = items.Count
        };
    }

    private async Task CollectExpiredSessionsForTenantAsync(ITenantRepository tenantRepository,
        List<ServerSideSession> removed, int count)
    {
        using var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtServerSideSession.ExpirationDateTime), FieldFilterOperator.LessEqualThan,
                DateTime.UtcNow);

        var remaining = count - removed.Count;
        var query = await tenantRepository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session,
            queryOptions, 0, remaining);

        foreach (var rtSession in query.Items)
        {
            try
            {
                await tenantRepository.DeleteOneRtEntityByRtIdAsync<RtServerSideSession>(session,
                    rtSession.RtId, DeleteOptions.Erase);
                removed.Add(mapper.Map<ServerSideSession>(rtSession));
            }
            catch (OperationFailedException ex)
            {
                Logger.Debug(
                    "Concurrency exception removing expired session '{RtId}' for tenant '{TenantId}': {Message}",
                    rtSession.RtId, tenantRepository.TenantId, ex.Message);
            }
        }

        await session.CommitTransactionAsync();
    }

    private static RtEntityQueryOptions CreateFilterQueryOptions(string? subjectId, string? sessionId)
    {
        var queryOptions = RtEntityQueryOptions.Create();
        if (!string.IsNullOrWhiteSpace(subjectId))
        {
            queryOptions.FieldFilter(nameof(RtServerSideSession.SubjectId), FieldFilterOperator.Equals, subjectId);
        }
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            queryOptions.FieldFilter(nameof(RtServerSideSession.SessionId), FieldFilterOperator.Equals, sessionId);
        }
        return queryOptions;
    }

    private static async Task<RtServerSideSession?> GetRtSessionByKeyAsync(ITenantRepository repository,
        IOctoSession session, string key)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtServerSideSession.SessionKey), FieldFilterOperator.Equals, key);

        var result = await repository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session, queryOptions);
        return result.Items.FirstOrDefault();
    }
}
