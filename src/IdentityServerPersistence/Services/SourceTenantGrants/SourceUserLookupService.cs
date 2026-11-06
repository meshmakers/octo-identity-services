using System.Security.Cryptography;
using System.Text;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.SourceTenantGrants;

/// <summary>The one user a source user lookup found (AB#8341). No e-mail address, no phone number.</summary>
public sealed record SourceUserLookupMatch(string SourceTenantId, string UserId, string UserName, string? DisplayName);

/// <summary>
///     Finds exactly one user of a source tenant S for an administrator of a target tenant T by exact user name or exact
///     e-mail (AB#8341, <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §2.1 and §3).
/// </summary>
public interface ISourceUserLookupService
{
    /// <summary>
    ///     The match, or <c>null</c> for every negative case alike: S empty or absent, S neither a registry ancestor of T
    ///     nor permitting T (<see cref="ISourceTenantGrantPolicy" />), identifier empty, no user or more than one user with
    ///     that exact user name / e-mail, a shadow (<c>xt_</c>) user, a locked-out or sign-in-blocked user.
    /// </summary>
    Task<SourceUserLookupMatch?> LookupAsync(string targetTenantId, string? sourceTenantId, string? identifier,
        string callerName, CancellationToken cancellationToken = default);
}

/// <inheritdoc />
/// <remarks>
///     <para>
///         No listing, no prefix, substring, wildcard or regular-expression semantics: the identifier is trimmed,
///         upper-cased like the stored <c>NormalizedUserName</c> / <c>NormalizedEmail</c> and compared for equality, as a
///         value (never as a query operator). <c>SearchUsersInTenantAsync</c> of the ancestor flow (substring, empty
///         search = first users) is deliberately not used.
///     </para>
///     <para>
///         Timing: every request runs the registry ancestry read, the policy and the same two equality queries. When S is
///         not a registered tenant (or empty) the queries run against T's database instead and their result is
///         discarded, so "tenant absent" does not answer measurably faster than "user absent". The permission decision is
///         applied only after the queries. Remaining differences: an unknown S may trigger the registry's throttled
///         miss refresh (at most once per <see cref="TenantRegistry.MissRefreshInterval" />), and a found user costs the
///         sign-in check; both are small against the database round trips.
///     </para>
///     <para>
///         The identifier is never logged in clear; logs carry a short SHA-256 prefix of the normalized value.
///     </para>
/// </remarks>
public sealed class SourceUserLookupService(
    ITenantRegistry tenantRegistry,
    ICrossTenantAncestryGuard ancestryGuard,
    ISourceTenantGrantPolicy grantPolicy,
    ISourceUserLookupAuditSink auditSink,
    IOptions<IdentityOptions> identityOptions,
    TimeProvider timeProvider,
    ILogger<SourceUserLookupService> logger) : ISourceUserLookupService
{
    /// <summary>Compared against nothing real: the query value when the identifier is empty.</summary>
    private const string EmptyIdentifierProbe = "\u0000";

    /// <inheritdoc />
    public async Task<SourceUserLookupMatch?> LookupAsync(string targetTenantId, string? sourceTenantId,
        string? identifier, string callerName, CancellationToken cancellationToken = default)
    {
        var source = sourceTenantId?.Trim() ?? string.Empty;
        var normalized = identifier?.Trim().ToUpperInvariant() ?? string.Empty;
        var hasInput = source.Length > 0 && normalized.Length > 0;

        // All parts of the decision are evaluated before it is taken: no early return before the user query.
        var ancestors = await ancestryGuard.GetRegistryAncestorsAsync(targetTenantId);
        var isAncestor = source.Length > 0 && ancestors.Contains(source, StringComparer.OrdinalIgnoreCase);
        var isPermitted = source.Length > 0 && await IsPermittedAsync(source, targetTenantId, cancellationToken);

        var sourceRepository = source.Length > 0 ? await tenantRegistry.TryGetRepositoryAsync(source) : null;
        var queryRepository = sourceRepository ?? await tenantRegistry.TryGetRepositoryAsync(targetTenantId);
        var candidates = await QueryAsync(queryRepository, normalized.Length > 0 ? normalized : EmptyIdentifierProbe,
            source, cancellationToken);

        var (match, outcome) = Decide(hasInput, sourceRepository != null, isAncestor || isPermitted,
            sourceRepository != null ? candidates : [], source);

        logger.LogInformation(
            "Source user lookup in {TargetTenantId} by {CallerName} for source tenant {SourceTenantId}: {Outcome} (identifier hash {IdentifierHash}, AB#8341)",
            targetTenantId, callerName, source, outcome, HashIdentifier(normalized));

        await RecordAuditAsync(new SourceUserLookupAuditEvent(targetTenantId, source, callerName, match != null,
            sourceRepository != null, match?.UserId, match?.UserName), cancellationToken);
        return match;
    }

    private (SourceUserLookupMatch? Match, string Outcome) Decide(bool hasInput, bool sourceExists, bool mayLookUp,
        IReadOnlyList<RtUser> candidates, string source)
    {
        if (!hasInput)
        {
            return (null, "miss: empty input");
        }

        if (!sourceExists)
        {
            return (null, "miss: source tenant unknown");
        }

        if (!mayLookUp)
        {
            return (null, "miss: source tenant is no registry ancestor and does not permit the target");
        }

        if (candidates.Count == 0)
        {
            return (null, "miss: no user");
        }

        if (candidates.Count > 1)
        {
            return (null, "miss: more than one user");
        }

        var user = candidates[0];
        if (CrossTenantShadowUserName.IsShadowUserName(user.UserName))
        {
            return (null, "miss: shadow user");
        }

        if (SourceUserSignInBlock.Get(user, identityOptions.Value.SignIn, timeProvider.GetUtcNow()) is { } block)
        {
            return (null, $"miss: user may not sign in ({block})");
        }

        return (new SourceUserLookupMatch(source, user.RtId.ToString(), user.UserName ?? string.Empty,
            DisplayName(user)), "hit");
    }

    private async Task<bool> IsPermittedAsync(string source, string targetTenantId, CancellationToken cancellationToken)
    {
        try
        {
            return await grantPolicy.IsPermittedAsync(source, targetTenantId, cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Source user lookup: the grant policy failed for source tenant {SourceTenantId} and target tenant {TargetTenantId}; treated as not permitted (AB#8341)",
                source, targetTenantId);
            return false;
        }
    }

    /// <summary>
    ///     The users whose normalized user name or normalized e-mail equals <paramref name="normalized" />, distinct by id.
    ///     Two equality queries, always both. A read error yields no user.
    /// </summary>
    private async Task<IReadOnlyList<RtUser>> QueryAsync(ITenantRepository? repository, string normalized,
        string source, CancellationToken cancellationToken)
    {
        if (repository == null)
        {
            return [];
        }

        try
        {
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();
            var byName = await repository.GetRtEntitiesByTypeAsync<RtUser>(session,
                RtEntityQueryOptions.Create().FieldEquals(nameof(RtUser.NormalizedUserName), normalized));
            var byEmail = await repository.GetRtEntitiesByTypeAsync<RtUser>(session,
                RtEntityQueryOptions.Create().FieldEquals(nameof(RtUser.NormalizedEmail), normalized));
            await session.CommitTransactionAsync();

            cancellationToken.ThrowIfCancellationRequested();
            return byName.Items.Concat(byEmail.Items).DistinctBy(u => u.RtId).ToList();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Source user lookup: users of source tenant {SourceTenantId} could not be read; answered as not found (AB#8341)",
                source);
            return [];
        }
    }

    private async Task RecordAuditAsync(SourceUserLookupAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        try
        {
            await auditSink.RecordAsync(auditEvent, cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Source user lookup: the audit event could not be recorded (AB#8341)");
        }
    }

    private static string? DisplayName(RtUser user)
    {
        var name = $"{user.FirstName} {user.LastName}".Trim();
        return name.Length > 0 ? name : null;
    }

    /// <summary>First 12 hex characters of the SHA-256 of the normalized identifier: correlates, never reveals.</summary>
    private static string HashIdentifier(string normalized)
        => normalized.Length == 0
            ? "-"
            : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)))[..12];
}
