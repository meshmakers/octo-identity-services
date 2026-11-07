using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.SourceTenantGrants;

/// <summary>
///     The source identity a mapping in target tenant T may be created for (AB#8343): the source tenant id as the tenant
///     registry stores it and the user id and user name read from the source tenant's own user record.
/// </summary>
/// <param name="SourceTenantId">The registry's spelling of the source tenant id.</param>
/// <param name="SourceUserId">The user's id in the source tenant.</param>
/// <param name="SourceUserName">The user name from the source tenant's user record — never the caller's input.</param>
/// <param name="IsRegistryAncestor">The source tenant is a registry ancestor of T (not a sibling grant).</param>
public sealed record SourceTenantGrantSource(
    string SourceTenantId,
    string SourceUserId,
    string SourceUserName,
    bool IsRegistryAncestor);

/// <summary>
///     The gate of <c>POST ExternalTenantUserMappings</c> (AB#8343, <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §2.2):
///     decides whether an administrator of target tenant T may create a mapping for a user of source tenant S.
/// </summary>
public interface ISourceTenantGrantAdmission
{
    /// <summary>
    ///     The admitted source identity, or <c>null</c> for every refusal alike (answered as one
    ///     <c>403 SourceTenantNotPermitted</c>): S empty or not registered; S neither a registry ancestor of T nor
    ///     permitting T (<see cref="ISourceTenantGrantPolicy" />); no user with that id in S; and — for a non-ancestor S
    ///     — a shadow (<c>xt_</c>) user or a user that may not sign in (locked out, sign-in rules; AB#7855).
    /// </summary>
    Task<SourceTenantGrantSource?> AdmitAsync(string targetTenantId, string? sourceTenantId, string? sourceUserId,
        CancellationToken cancellationToken = default);
}

/// <inheritdoc />
/// <remarks>
///     <para>
///         Ancestry is the tenant registry only (<see cref="ICrossTenantAncestryGuard.GetRegistryAncestorsAsync" />), like
///         the lookup of AB#8341: <c>CrossTenantAncestry=Warn</c> does not widen this route, because under <c>Warn</c> the
///         guard trusts every claimed tenant.
///     </para>
///     <para>
///         The user is always read from S, also for an ancestor S (including the system tenant): a mapping, and the grant
///         events it writes into S (AB#8342), name a user S really has, with S's spelling of the user name (Ariadne's
///         review of AB#8436). The caller's <c>sourceUserName</c> is not used.
///     </para>
///     <para>
///         Every part of the decision is evaluated before it is taken; when S is not registered, the user read runs
///         against T's database and is discarded, so "tenant absent" does not answer measurably faster than "user absent".
///     </para>
/// </remarks>
public sealed class SourceTenantGrantAdmission(
    ITenantRegistry tenantRegistry,
    ICrossTenantAncestryGuard ancestryGuard,
    ISourceTenantGrantPolicy grantPolicy,
    IOptions<IdentityOptions> identityOptions,
    TimeProvider timeProvider,
    ILogger<SourceTenantGrantAdmission> logger) : ISourceTenantGrantAdmission
{
    /// <inheritdoc />
    public async Task<SourceTenantGrantSource?> AdmitAsync(string targetTenantId, string? sourceTenantId,
        string? sourceUserId, CancellationToken cancellationToken = default)
    {
        var source = sourceTenantId?.Trim() ?? string.Empty;
        var userId = sourceUserId?.Trim() ?? string.Empty;

        var ancestors = await ancestryGuard.GetRegistryAncestorsAsync(targetTenantId);
        var isAncestor = source.Length > 0 && ancestors.Contains(source, StringComparer.OrdinalIgnoreCase);
        var isPermitted = source.Length > 0 && !isAncestor &&
                          await IsPermittedAsync(source, targetTenantId, cancellationToken);

        var registered = source.Length > 0 ? await tenantRegistry.TryGetTenantAsync(source) : null;
        var sourceRepository = registered != null ? await tenantRegistry.TryGetRepositoryAsync(source) : null;
        var queryRepository = sourceRepository ?? await tenantRegistry.TryGetRepositoryAsync(targetTenantId);
        var user = await ReadUserAsync(queryRepository, userId, source, cancellationToken);
        if (sourceRepository == null)
        {
            user = null;
        }

        var (admitted, outcome) = Decide(source, userId, registered, isAncestor, isPermitted, user);
        logger.LogInformation(
            "Mapping create in {TargetTenantId} for user {SourceUserId} of source tenant {SourceTenantId}: {Outcome} (AB#8343)",
            targetTenantId, userId, source, outcome);
        return admitted;
    }

    private (SourceTenantGrantSource? Admitted, string Outcome) Decide(string source, string userId,
        Meshmakers.Octo.Runtime.Contracts.MongoDb.OctoTenant? registered, bool isAncestor, bool isPermitted,
        RtUser? user)
    {
        if (source.Length == 0 || userId.Length == 0)
        {
            return (null, "refused: empty source tenant or user id");
        }

        if (registered == null)
        {
            return (null, "refused: source tenant unknown");
        }

        if (!isAncestor && !isPermitted)
        {
            return (null, "refused: source tenant is no registry ancestor and does not permit the target");
        }

        if (user == null)
        {
            return (null, "refused: no such user in the source tenant");
        }

        if (!isAncestor)
        {
            if (CrossTenantShadowUserName.IsShadowUserName(user.UserName))
            {
                return (null, "refused: shadow user");
            }

            if (SourceUserSignInBlock.Get(user, identityOptions.Value.SignIn, timeProvider.GetUtcNow()) is { } block)
            {
                return (null, $"refused: user may not sign in ({block})");
            }
        }

        return (new SourceTenantGrantSource(registered.TenantId, user.RtId.ToString(), user.UserName ?? string.Empty,
            isAncestor), isAncestor ? "admitted: registry ancestor" : "admitted: permitted by the source tenant");
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
                "Mapping create: the grant policy failed for source tenant {SourceTenantId} and target tenant {TargetTenantId}; treated as not permitted (AB#8343)",
                source, targetTenantId);
            return false;
        }
    }

    /// <summary>The user with id <paramref name="userId" />; a malformed id or a read error yields none.</summary>
    private async Task<RtUser?> ReadUserAsync(ITenantRepository? repository, string userId, string source,
        CancellationToken cancellationToken)
    {
        if (repository == null || !OctoObjectId.TryParse(userId, out var rtId))
        {
            return null;
        }

        try
        {
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();
            var user = await repository.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
            await session.CommitTransactionAsync();
            cancellationToken.ThrowIfCancellationRequested();
            return user;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Mapping create: the user of source tenant {SourceTenantId} could not be read; answered as not permitted (AB#8343)",
                source);
            return null;
        }
    }
}
