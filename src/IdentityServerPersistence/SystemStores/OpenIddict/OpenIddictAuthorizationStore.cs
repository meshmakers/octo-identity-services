using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NLog;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     OpenIddict authorization store over the per-tenant <see cref="RtOAuthAuthorization" /> CK
///     entities (AB#4991): the durable subject↔client↔scopes link (permanent authorizations =
///     remembered consent; ad-hoc authorizations tie the tokens of one flow together). Stored
///     per tenant like <see cref="OpenIddictTokenStore" />.
/// </summary>
public class OpenIddictAuthorizationStore(IMultiTenancyResolverService multiTenancyResolverService)
    : IOpenIddictAuthorizationStore<RtOAuthAuthorization>
{
    private const int CleanupBatchSize = 50;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthAuthorization>(
            session, RtEntityQueryOptions.Create(), 0, 1);
        await session.CommitTransactionAsync();
        return result.TotalCount;
    }

    public ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RtOAuthAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the authorization store are not supported.");

    public async ValueTask CreateAsync(RtOAuthAuthorization authorization, CancellationToken cancellationToken)
    {
        await MongoWriteRetry.ExecuteWithRetryAsync(async () =>
        {
            using var session = await TenantRepository.GetSessionAsync();
            session.StartTransaction();
            await TenantRepository.InsertOneRtEntityAsync(session, authorization);
            await session.CommitTransactionAsync();
        });
    }

    public async ValueTask DeleteAsync(RtOAuthAuthorization authorization, CancellationToken cancellationToken)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var filter = FieldFilterCriteria.Create(LogicalOperators.And)
            .FieldEquals(nameof(RtOAuthAuthorization.RtId), authorization.RtId.ToString());
        await TenantRepository.DeleteManyRtEntitiesAsync<RtOAuthAuthorization>(session, filter, DeleteOptions.Erase);
        await session.CommitTransactionAsync();
    }

    public async IAsyncEnumerable<RtOAuthAuthorization> FindAsync(
        string? subject, string? client, string? status, string? type, ImmutableArray<string>? scopes,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var queryOptions = RtEntityQueryOptions.Create();
        if (!string.IsNullOrEmpty(subject))
        {
            queryOptions.FieldFilter(nameof(RtOAuthAuthorization.SubjectId), FieldFilterOperator.Equals, subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            queryOptions.FieldFilter(nameof(RtOAuthAuthorization.ClientId), FieldFilterOperator.Equals, client);
        }

        if (!string.IsNullOrEmpty(status))
        {
            queryOptions.FieldFilter(nameof(RtOAuthAuthorization.Status), FieldFilterOperator.Equals, status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            queryOptions.FieldFilter(nameof(RtOAuthAuthorization.AuthorizationType), FieldFilterOperator.Equals,
                type);
        }

        await foreach (var authorization in QueryAsync(queryOptions, cancellationToken))
        {
            // Scope filtering happens in memory: the authorization must contain every requested scope.
            if (scopes is { } requiredScopes &&
                !requiredScopes.All(s => authorization.Scopes?.Contains(s) == true))
            {
                continue;
            }

            yield return authorization;
        }
    }

    public IAsyncEnumerable<RtOAuthAuthorization> FindByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken)
        => QueryAsync(RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtOAuthAuthorization.ClientId), FieldFilterOperator.Equals, identifier),
            cancellationToken);

    public async ValueTask<RtOAuthAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (!OctoObjectId.TryParse(identifier, out _))
        {
            return null;
        }

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtOAuthAuthorization.RtId), FieldFilterOperator.Equals, identifier);
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthAuthorization>(session, queryOptions);
        await session.CommitTransactionAsync();
        return result.Items.FirstOrDefault();
    }

    public IAsyncEnumerable<RtOAuthAuthorization> FindBySubjectAsync(
        string subject, CancellationToken cancellationToken)
        => QueryAsync(RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtOAuthAuthorization.SubjectId), FieldFilterOperator.Equals, subject),
            cancellationToken);

    public ValueTask<string?> GetApplicationIdAsync(
        RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(authorization.ClientId);

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RtOAuthAuthorization>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the authorization store are not supported.");

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(
        RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(authorization.CreationDateTime.HasValue
            ? new DateTimeOffset(DateTime.SpecifyKind(authorization.CreationDateTime.Value, DateTimeKind.Utc))
            : null);

    public ValueTask<string?> GetIdAsync(RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(authorization.RtId.ToString());

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(OpenIddictTokenStore.DeserializeProperties(authorization.Properties));

    public ValueTask<ImmutableArray<string>> GetScopesAsync(
        RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(authorization.Scopes?.ToImmutableArray() ?? ImmutableArray<string>.Empty);

    public ValueTask<string?> GetStatusAsync(RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(authorization.Status);

    public ValueTask<string?> GetSubjectAsync(RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(authorization.SubjectId);

    public ValueTask<string?> GetTypeAsync(RtOAuthAuthorization authorization, CancellationToken cancellationToken)
        => new(authorization.AuthorizationType);

    public ValueTask<RtOAuthAuthorization> InstantiateAsync(CancellationToken cancellationToken)
        => new(new RtOAuthAuthorization { RtId = OctoObjectId.GenerateNewId() });

    public IAsyncEnumerable<RtOAuthAuthorization> ListAsync(
        int? count, int? offset, CancellationToken cancellationToken)
        => throw new NotSupportedException("Listing authorizations through OpenIddict is not supported.");

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RtOAuthAuthorization>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the authorization store are not supported.");

    public async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        // Remove authorizations created before the threshold that are no longer valid, plus
        // ad-hoc authorizations (flow-scoped, their tokens are pruned by the token store on the
        // same sweep). Permanent valid authorizations (remembered consent) are kept.
        long removed = 0;
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtOAuthAuthorization.CreationDateTime), FieldFilterOperator.LessEqualThan,
                threshold.UtcDateTime);

        var found = int.MaxValue;
        while (found >= CleanupBatchSize && !cancellationToken.IsCancellationRequested)
        {
            var query = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthAuthorization>(
                session, queryOptions, 0, CleanupBatchSize * 4);
            var prunable = query.Items
                .Where(a => !string.Equals(a.Status, Statuses.Valid, StringComparison.Ordinal) ||
                            string.Equals(a.AuthorizationType, AuthorizationTypes.AdHoc, StringComparison.Ordinal))
                .Take(CleanupBatchSize)
                .ToList();

            found = query.Items.Count() >= CleanupBatchSize * 4 ? int.MaxValue : prunable.Count;
            if (prunable.Count == 0)
            {
                break;
            }

            var deletedCount = 0;
            foreach (var authorization in prunable)
            {
                try
                {
                    await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtOAuthAuthorization>(
                        session, authorization.RtId, DeleteOptions.Erase);
                    deletedCount++;
                    removed++;
                }
                catch (OperationFailedException ex)
                {
                    Logger.Debug("Concurrency exception pruning authorization '{RtId}': {Message}",
                        authorization.RtId, ex.Message);
                }
            }

            if (deletedCount == 0)
            {
                Logger.Warn("Stopping authorization pruning: no entries could be deleted from the current batch");
                break;
            }
        }

        await session.CommitTransactionAsync();
        return removed;
    }

    public async ValueTask<long> RevokeAsync(
        string? subject, string? client, string? status, string? type, CancellationToken cancellationToken)
    {
        long revoked = 0;
        var authorizations = new List<RtOAuthAuthorization>();
        await foreach (var authorization in FindAsync(subject, client, status, type, null, cancellationToken))
        {
            authorizations.Add(authorization);
        }

        foreach (var authorization in authorizations)
        {
            authorization.Status = Statuses.Revoked;
            await UpdateAsync(authorization, cancellationToken);
            revoked++;
        }

        return revoked;
    }

    public async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        => await RevokeAsync(null, identifier, null, null, cancellationToken);

    public async ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
        => await RevokeAsync(subject, null, null, null, cancellationToken);

    public ValueTask SetApplicationIdAsync(
        RtOAuthAuthorization authorization, string? identifier, CancellationToken cancellationToken)
    {
        authorization.ClientId = identifier ?? string.Empty;
        return default;
    }

    public ValueTask SetCreationDateAsync(
        RtOAuthAuthorization authorization, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        authorization.CreationDateTime = date?.UtcDateTime;
        return default;
    }

    public ValueTask SetPropertiesAsync(RtOAuthAuthorization authorization,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        authorization.Properties = OpenIddictTokenStore.SerializeProperties(properties);
        return default;
    }

    public ValueTask SetScopesAsync(RtOAuthAuthorization authorization, ImmutableArray<string> scopes,
        CancellationToken cancellationToken)
    {
        authorization.Scopes = new AttributeStringValueList(scopes.ToList());
        return default;
    }

    public ValueTask SetStatusAsync(RtOAuthAuthorization authorization, string? status,
        CancellationToken cancellationToken)
    {
        authorization.Status = status;
        return default;
    }

    public ValueTask SetSubjectAsync(RtOAuthAuthorization authorization, string? subject,
        CancellationToken cancellationToken)
    {
        authorization.SubjectId = subject;
        return default;
    }

    public ValueTask SetTypeAsync(RtOAuthAuthorization authorization, string? type,
        CancellationToken cancellationToken)
    {
        authorization.AuthorizationType = type;
        return default;
    }

    public async ValueTask UpdateAsync(RtOAuthAuthorization authorization, CancellationToken cancellationToken)
    {
        await MongoWriteRetry.ExecuteWithRetryAsync(async () =>
        {
            using var session = await TenantRepository.GetSessionAsync();
            session.StartTransaction();
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, authorization.RtId, authorization);
            await session.CommitTransactionAsync();
        });
    }

    private async IAsyncEnumerable<RtOAuthAuthorization> QueryAsync(
        RtEntityQueryOptions queryOptions, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthAuthorization>(session, queryOptions);
        await session.CommitTransactionAsync();

        foreach (var authorization in result.Items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return authorization;
        }
    }
}
