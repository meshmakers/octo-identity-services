using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.SourceTenantGrants;

/// <summary>
///     The production <see cref="ISourceTenantGrantPolicy" /> (AB#8345, decision 2026-11-06 option A): source tenant S
///     permits target tenant T exactly when T is on the allow-list S's administrators keep in S
///     (<see cref="ICrossTenantGrantPermissionStore" />). Default for every tenant: empty list = nobody.
/// </summary>
/// <remarks>
///     <para>
///         Read on every call, no cache: when S removes T, lookups and new grants from T stop with the next request
///         (and the exchange gate of AB#8343/AB#8344, which asks the same policy, refuses at the next exchange).
///     </para>
///     <para>
///         Fails closed and quietly: an unknown S, an unreadable registry or an unreadable row answer <c>false</c> and
///         never throw. When S is not a registered tenant, the same configuration read runs against T's database and its
///         result is discarded, so "S absent" costs the same round trip as "S does not permit T" (the uniform-404 rule of
///         the lookup, concept §3).
///     </para>
/// </remarks>
public sealed class AllowListSourceTenantGrantPolicy(
    ITenantRegistry tenantRegistry,
    ICrossTenantGrantPermissionStore permissionStore,
    ILogger<AllowListSourceTenantGrantPolicy> logger) : ISourceTenantGrantPolicy
{
    /// <inheritdoc />
    public async Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId,
        CancellationToken cancellationToken = default)
    {
        var source = sourceTenantId?.Trim() ?? string.Empty;
        var target = targetTenantId?.Trim() ?? string.Empty;
        if (source.Length == 0 || target.Length == 0)
        {
            return false;
        }

        try
        {
            var sourceRepository = await tenantRegistry.TryGetRepositoryAsync(source);
            var readRepository = sourceRepository ?? await tenantRegistry.TryGetRepositoryAsync(target);
            if (readRepository == null)
            {
                return false;
            }

            var permissions = await permissionStore.GetAsync(readRepository);
            cancellationToken.ThrowIfCancellationRequested();

            return sourceRepository != null &&
                   !string.Equals(source, target, StringComparison.OrdinalIgnoreCase) &&
                   permissions.TargetTenantIds.Contains(target, StringComparer.OrdinalIgnoreCase);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Cross-tenant grant permission of source tenant {SourceTenantId} for target tenant {TargetTenantId} could not be read; treated as not permitted (AB#8345)",
                source, target);
            return false;
        }
    }
}
