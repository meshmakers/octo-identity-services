using System.Diagnostics.Metrics;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services;

/// <summary>
///     One pass of the client mirror reconciliation (AB#8019) over every tenant of the instance.
/// </summary>
public interface IClientMirrorReconciliationJob
{
    /// <summary>
    ///     Reconciles the mirrors tracked in the system tenant and in every registered tenant
    ///     (<see cref="IClientMirrorProvisioningService.ReconcileMirrorsAsync" />) and returns the sum.
    ///     A failing tenant is logged and counted; it does not stop the pass.
    /// </summary>
    Task<ClientMirrorReconciliationResult> RunOnceAsync(CancellationToken cancellationToken = default);
}

/// <summary>
///     Compensation for the best-effort mirror sync after a client change (AB#8019, decision OD-6 "guidance only,
///     no outbox"). A client write commits first; the copy into the child-tenant mirrors runs afterwards and may fail
///     (child database unreachable, timeout, crash). Before this job only the next identity start repaired such a
///     mirror, so a secret removed in the parent stayed valid in the child tenants until then. The hosted service calls
///     this pass every <c>Identity:ClientMirrorReconciliationInterval</c> seconds, which bounds that window.
/// </summary>
/// <remarks>
///     <b>Replicas.</b> Every identity replica runs the pass; there is no leader election or lock. That is safe because
///     the work is idempotent and guarded: a mirror in sync is not written, and every writer of a mirror (sync,
///     provisioning, rotation, this pass) writes with the version it read and retries on a conflict (see
///     <see cref="ClientMirrorProvisioningService" />). Two replicas repairing the same mirror at once converge on the
///     same state; a re-created mirror is claimed by a version-checked write of its tracking row. The cost is one read of the tracking rows per
///     tenant and two reads per tracked mirror per pass.
/// </remarks>
public class ClientMirrorReconciliationJob(
    ISystemContext systemContext,
    IClientMirrorProvisioningService mirrorProvisioningService,
    ILogger<ClientMirrorReconciliationJob> logger) : IClientMirrorReconciliationJob
{
    public async Task<ClientMirrorReconciliationResult> RunOnceAsync(CancellationToken cancellationToken = default)
    {
        var tenantIds = await GetTenantIdsAsync();
        var total = ClientMirrorReconciliationResult.Empty;
        var failedTenants = 0;
        foreach (var tenantId in tenantIds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                total = total.Add(await mirrorProvisioningService.ReconcileMirrorsAsync(tenantId, cancellationToken));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Warning, not Error: a half-provisioned tenant would otherwise raise an error on every pass.
                failedTenants++;
                logger.LogWarning(ex, "Client mirror reconciliation failed for parent tenant '{TenantId}'", tenantId);
            }
        }

        ClientMirrorReconciliationMetrics.Record(total, failedTenants);
        if (total.MirrorsRepaired + total.MirrorsRemoved + total.MirrorsFailed + failedTenants > 0)
        {
            logger.LogInformation(
                "Client mirror reconciliation: checked={Checked} inSync={InSync} repaired={Repaired} removed={Removed} "
                + "skipped={Skipped} failed={Failed} failedTenants={FailedTenants}",
                total.MirrorsChecked, total.MirrorsInSync, total.MirrorsRepaired, total.MirrorsRemoved,
                total.MirrorsSkipped, total.MirrorsFailed, failedTenants);
        }
        else
        {
            logger.LogDebug("Client mirror reconciliation: checked={Checked}, all in sync", total.MirrorsChecked);
        }

        return total;
    }

    private async Task<IReadOnlyList<string>> GetTenantIdsAsync()
    {
        var ids = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(systemContext.TenantId) && seen.Add(systemContext.TenantId))
        {
            ids.Add(systemContext.TenantId);
        }

        if (!await systemContext.IsSystemTenantExistingAsync())
        {
            return ids;
        }

        using var adminSession = await systemContext.GetAdminSessionAsync();
        adminSession.StartTransaction();
        var tenants = await systemContext.GetAllTenantsAsync(adminSession);
        await adminSession.CommitTransactionAsync();
        foreach (var tenant in tenants.Items)
        {
            if (!string.IsNullOrWhiteSpace(tenant.TenantId) && seen.Add(tenant.TenantId))
            {
                ids.Add(tenant.TenantId);
            }
        }

        return ids;
    }
}

/// <summary>
///     Metrics of the client mirror reconciliation (AB#8019), meter <see cref="MeterName" />. Labels carry the outcome
///     only: never a tenant, client id, secret or hash.
/// </summary>
public static class ClientMirrorReconciliationMetrics
{
    /// <summary>Meter name; registered on the meter provider of the identity service.</summary>
    public const string MeterName = "Meshmakers.Octo.Identity";

    private static readonly Meter Meter = new(MeterName);

    /// <summary>
    ///     <c>identity.client_mirror.reconciled</c>: mirrors per pass by <c>outcome</c> = <c>repaired</c>, <c>removed</c>,
    ///     <c>skipped</c>, <c>failed</c> (mirrors in sync are not counted).
    /// </summary>
    internal static readonly Counter<long> Reconciled = Meter.CreateCounter<long>(
        "identity.client_mirror.reconciled", "{mirror}",
        "Client mirrors the periodic reconciliation repaired, removed, skipped or failed on");

    /// <summary><c>identity.client_mirror.reconcile.runs</c>: passes by <c>outcome</c> = <c>ok</c> or <c>tenant_failed</c>.</summary>
    internal static readonly Counter<long> Runs = Meter.CreateCounter<long>(
        "identity.client_mirror.reconcile.runs", "{run}", "Passes of the client mirror reconciliation");

    internal static void Record(ClientMirrorReconciliationResult result, int failedTenants)
    {
        Add("repaired", result.MirrorsRepaired);
        Add("removed", result.MirrorsRemoved);
        Add("skipped", result.MirrorsSkipped);
        Add("failed", result.MirrorsFailed);
        Runs.Add(1, new KeyValuePair<string, object?>("outcome", failedTenants > 0 ? "tenant_failed" : "ok"));
    }

    private static void Add(string outcome, int count)
    {
        if (count > 0)
        {
            Reconciled.Add(count, new KeyValuePair<string, object?>("outcome", outcome));
        }
    }
}
