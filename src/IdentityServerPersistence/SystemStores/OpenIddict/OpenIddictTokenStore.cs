using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using NLog;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     OpenIddict token store over the per-tenant <see cref="RtOAuthToken" /> CK entities
///     (AB#4991): authorization codes, refresh tokens and device/user codes. Tokens are stored in
///     the tenant database resolved from the current HTTP context (same per-tenant strategy as
///     <see cref="PersistentGrantStore" /> since AB#1586); <c>OidcTenantResolutionMiddleware</c>
///     wires the tenant before OpenIddict processes the request.
/// </summary>
/// <remarks>
///     The token identifier exposed to OpenIddict is the entity <c>RtId</c>. Concurrent writes
///     (token status flips on redemption) share the <see cref="MongoWriteRetry" /> behavior of the
///     sibling stores. Expired-entry cleanup runs through <see cref="PruneAsync" />, invoked by
///     <c>TokenCleanupHostService</c> for the system tenant and every child tenant (AB#4994).
/// </remarks>
public class OpenIddictTokenStore(IMultiTenancyResolverService multiTenancyResolverService)
    : IOpenIddictTokenStore<RtOAuthToken>
{
    private const int CleanupBatchSize = 50;

    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthToken>(
            session, RtEntityQueryOptions.Create(), 0, 1);
        await session.CommitTransactionAsync();
        return result.TotalCount;
    }

    public ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<RtOAuthToken>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the token store are not supported.");

    public async ValueTask CreateAsync(RtOAuthToken token, CancellationToken cancellationToken)
    {
        await MongoWriteRetry.ExecuteWithRetryAsync(async () =>
        {
            using var session = await TenantRepository.GetSessionAsync();
            session.StartTransaction();
            await TenantRepository.InsertOneRtEntityAsync(session, token);
            await session.CommitTransactionAsync();
        });
    }

    public async ValueTask DeleteAsync(RtOAuthToken token, CancellationToken cancellationToken)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var filter = FieldFilterCriteria.Create(LogicalOperators.And)
            .FieldEquals(nameof(RtOAuthToken.RtId), token.RtId.ToString());
        await TenantRepository.DeleteManyRtEntitiesAsync<RtOAuthToken>(session, filter, DeleteOptions.Erase);
        await session.CommitTransactionAsync();
    }

    public IAsyncEnumerable<RtOAuthToken> FindAsync(
        string? subject, string? client, string? status, string? type, CancellationToken cancellationToken)
    {
        var queryOptions = RtEntityQueryOptions.Create();
        if (!string.IsNullOrEmpty(subject))
        {
            queryOptions.FieldFilter(nameof(RtOAuthToken.SubjectId), FieldFilterOperator.Equals, subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            queryOptions.FieldFilter(nameof(RtOAuthToken.ClientId), FieldFilterOperator.Equals, client);
        }

        if (!string.IsNullOrEmpty(status))
        {
            queryOptions.FieldFilter(nameof(RtOAuthToken.Status), FieldFilterOperator.Equals, status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            queryOptions.FieldFilter(nameof(RtOAuthToken.TokenType), FieldFilterOperator.Equals, type);
        }

        return QueryAsync(queryOptions, cancellationToken);
    }

    public IAsyncEnumerable<RtOAuthToken> FindByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken)
        => QueryAsync(RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtOAuthToken.ClientId), FieldFilterOperator.Equals, identifier), cancellationToken);

    public IAsyncEnumerable<RtOAuthToken> FindByAuthorizationIdAsync(
        string identifier, CancellationToken cancellationToken)
        => QueryAsync(RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtOAuthToken.AuthorizationRtId), FieldFilterOperator.Equals, identifier),
            cancellationToken);

    public async ValueTask<RtOAuthToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (!OctoObjectId.TryParse(identifier, out _))
        {
            return null;
        }

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtOAuthToken.RtId), FieldFilterOperator.Equals, identifier);
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthToken>(session, queryOptions);
        await session.CommitTransactionAsync();
        return result.Items.FirstOrDefault();
    }

    public async ValueTask<RtOAuthToken?> FindByReferenceIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtOAuthToken.ReferenceId), FieldFilterOperator.Equals, identifier);
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthToken>(session, queryOptions);
        await session.CommitTransactionAsync();
        return result.Items.FirstOrDefault();
    }

    public IAsyncEnumerable<RtOAuthToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
        => QueryAsync(RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtOAuthToken.SubjectId), FieldFilterOperator.Equals, subject), cancellationToken);

    public ValueTask<string?> GetApplicationIdAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.ClientId);

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<RtOAuthToken>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the token store are not supported.");

    public ValueTask<string?> GetAuthorizationIdAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.AuthorizationRtId);

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(ToOffset(token.CreationDateTime));

    public ValueTask<DateTimeOffset?> GetExpirationDateAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(ToOffset(token.ExpirationDateTime));

    public ValueTask<string?> GetIdAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.RtId.ToString());

    public ValueTask<string?> GetPayloadAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.Payload);

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        RtOAuthToken token, CancellationToken cancellationToken)
        => new(DeserializeProperties(token.Properties));

    public ValueTask<DateTimeOffset?> GetRedemptionDateAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(ToOffset(token.RedemptionDateTime));

    public ValueTask<string?> GetReferenceIdAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.ReferenceId);

    public ValueTask<string?> GetStatusAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.Status);

    public ValueTask<string?> GetSubjectAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.SubjectId);

    public ValueTask<string?> GetTypeAsync(RtOAuthToken token, CancellationToken cancellationToken)
        => new(token.TokenType);

    public ValueTask<RtOAuthToken> InstantiateAsync(CancellationToken cancellationToken)
        => new(new RtOAuthToken { RtId = OctoObjectId.GenerateNewId() });

    public IAsyncEnumerable<RtOAuthToken> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => throw new NotSupportedException("Listing tokens through OpenIddict is not supported.");

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<RtOAuthToken>, TState, IQueryable<TResult>> query, TState state,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("LINQ queries against the token store are not supported.");

    public async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        // Remove tokens that were created before the threshold and can no longer be redeemed:
        // no longer valid, or past their expiration. Mirrors OpenIddict's EF/Mongo store
        // semantics and the batch/concurrency behavior of the former grant cleanup.
        long removed = 0;
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtOAuthToken.CreationDateTime), FieldFilterOperator.LessEqualThan,
                threshold.UtcDateTime);

        var found = int.MaxValue;
        while (found >= CleanupBatchSize && !cancellationToken.IsCancellationRequested)
        {
            var query = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthToken>(
                session, queryOptions, 0, CleanupBatchSize * 4);
            var prunable = query.Items
                .Where(t => !string.Equals(t.Status, Statuses.Valid, StringComparison.Ordinal) ||
                            (t.ExpirationDateTime.HasValue && t.ExpirationDateTime.Value <= DateTime.UtcNow))
                .Take(CleanupBatchSize)
                .ToList();

            found = query.Items.Count() >= CleanupBatchSize * 4 ? int.MaxValue : prunable.Count;
            if (prunable.Count == 0)
            {
                break;
            }

            var deletedCount = 0;
            foreach (var token in prunable)
            {
                try
                {
                    await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtOAuthToken>(
                        session, token.RtId, DeleteOptions.Erase);
                    deletedCount++;
                    removed++;
                }
                catch (OperationFailedException ex)
                {
                    Logger.Debug("Concurrency exception pruning token '{RtId}': {Message}",
                        token.RtId, ex.Message);
                }
            }

            if (deletedCount == 0)
            {
                Logger.Warn("Stopping token pruning: no tokens could be deleted from the current batch");
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
        var tokens = new List<RtOAuthToken>();
        await foreach (var token in FindAsync(subject, client, status, type, cancellationToken))
        {
            tokens.Add(token);
        }

        foreach (var token in tokens)
        {
            token.Status = Statuses.Revoked;
            await UpdateAsync(token, cancellationToken);
            revoked++;
        }

        return revoked;
    }

    public async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        => await RevokeAsync(null, identifier, null, null, cancellationToken);

    public async ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        long revoked = 0;
        var tokens = new List<RtOAuthToken>();
        await foreach (var token in FindByAuthorizationIdAsync(identifier, cancellationToken))
        {
            tokens.Add(token);
        }

        foreach (var token in tokens)
        {
            token.Status = Statuses.Revoked;
            await UpdateAsync(token, cancellationToken);
            revoked++;
        }

        return revoked;
    }

    public async ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
        => await RevokeAsync(subject, null, null, null, cancellationToken);

    public ValueTask SetApplicationIdAsync(RtOAuthToken token, string? identifier, CancellationToken cancellationToken)
    {
        token.ClientId = identifier;
        return default;
    }

    public ValueTask SetAuthorizationIdAsync(RtOAuthToken token, string? identifier, CancellationToken cancellationToken)
    {
        token.AuthorizationRtId = identifier;
        return default;
    }

    public ValueTask SetCreationDateAsync(RtOAuthToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        token.CreationDateTime = date?.UtcDateTime;
        return default;
    }

    public ValueTask SetExpirationDateAsync(RtOAuthToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        token.ExpirationDateTime = date?.UtcDateTime;
        return default;
    }

    public ValueTask SetPayloadAsync(RtOAuthToken token, string? payload, CancellationToken cancellationToken)
    {
        token.Payload = payload;
        return default;
    }

    public ValueTask SetPropertiesAsync(RtOAuthToken token,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        token.Properties = SerializeProperties(properties);
        return default;
    }

    public ValueTask SetRedemptionDateAsync(RtOAuthToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        token.RedemptionDateTime = date?.UtcDateTime;
        return default;
    }

    public ValueTask SetReferenceIdAsync(RtOAuthToken token, string? identifier, CancellationToken cancellationToken)
    {
        token.ReferenceId = identifier;
        return default;
    }

    public ValueTask SetStatusAsync(RtOAuthToken token, string? status, CancellationToken cancellationToken)
    {
        token.Status = status;
        return default;
    }

    public ValueTask SetSubjectAsync(RtOAuthToken token, string? subject, CancellationToken cancellationToken)
    {
        token.SubjectId = subject;
        return default;
    }

    public ValueTask SetTypeAsync(RtOAuthToken token, string? type, CancellationToken cancellationToken)
    {
        token.TokenType = type;
        return default;
    }

    public async ValueTask UpdateAsync(RtOAuthToken token, CancellationToken cancellationToken)
    {
        await MongoWriteRetry.ExecuteWithRetryAsync(async () =>
        {
            using var session = await TenantRepository.GetSessionAsync();
            session.StartTransaction();
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, token.RtId, token);
            await session.CommitTransactionAsync();
        });
    }

    internal static ImmutableDictionary<string, JsonElement> DeserializeProperties(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return ImmutableDictionary<string, JsonElement>.Empty;
        }

        using var document = JsonDocument.Parse(json);
        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            builder[property.Name] = property.Value.Clone();
        }

        return builder.ToImmutable();
    }

    internal static string? SerializeProperties(ImmutableDictionary<string, JsonElement> properties)
    {
        if (properties.IsEmpty)
        {
            return null;
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var property in properties)
            {
                writer.WritePropertyName(property.Key);
                property.Value.WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    private async IAsyncEnumerable<RtOAuthToken> QueryAsync(
        RtEntityQueryOptions queryOptions, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();
        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtOAuthToken>(session, queryOptions);
        await session.CommitTransactionAsync();

        foreach (var token in result.Items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return token;
        }
    }

    private static DateTimeOffset? ToOffset(DateTime? value)
        => value.HasValue ? new DateTimeOffset(DateTime.SpecifyKind(value.Value, DateTimeKind.Utc)) : null;
}
