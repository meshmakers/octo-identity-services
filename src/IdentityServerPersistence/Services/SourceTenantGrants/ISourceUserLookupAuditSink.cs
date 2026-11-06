namespace IdentityServerPersistence.Services.SourceTenantGrants;

/// <summary>
///     One source user lookup (AB#8341) as the audit story AB#8342 records it (<c>CrossTenantLookup</c> hit / miss, in T
///     and — when S exists — in S). Never carries the looked-up identifier, an e-mail address or a token.
/// </summary>
/// <param name="TargetTenantId">T, the tenant the caller administers (the request tenant).</param>
/// <param name="SourceTenantId">S as the caller typed it (may name no tenant).</param>
/// <param name="CallerName">The caller's user name or client id.</param>
/// <param name="IsHit">Whether exactly one user was returned.</param>
/// <param name="SourceTenantExists">Whether S is a registered tenant (AB#8342 writes a miss for an absent S only into T).</param>
/// <param name="SourceUserId">The returned user's id in S; <c>null</c> for a miss.</param>
/// <param name="SourceUserName">The returned user's name in S; <c>null</c> for a miss.</param>
public sealed record SourceUserLookupAuditEvent(
    string TargetTenantId,
    string SourceTenantId,
    string CallerName,
    bool IsHit,
    bool SourceTenantExists,
    string? SourceUserId,
    string? SourceUserName);

/// <summary>
///     Hook for the audit events of the source user lookup. AB#8342 replaces the registration with the implementation
///     that writes into the runtime event logs of T and S; until then <see cref="NoOpSourceUserLookupAuditSink" />.
///     An implementation must never throw into the request (log the failure instead).
/// </summary>
public interface ISourceUserLookupAuditSink
{
    /// <summary>Records one lookup.</summary>
    Task RecordAsync(SourceUserLookupAuditEvent auditEvent, CancellationToken cancellationToken = default);
}

/// <summary>No audit until AB#8342 (the lookup itself is logged without the identifier).</summary>
public sealed class NoOpSourceUserLookupAuditSink : ISourceUserLookupAuditSink
{
    /// <inheritdoc />
    public Task RecordAsync(SourceUserLookupAuditEvent auditEvent, CancellationToken cancellationToken = default)
        => Task.CompletedTask;
}
