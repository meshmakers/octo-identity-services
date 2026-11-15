using System.Collections.Concurrent;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.TenantLifecycle;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.TenantOwnership;

namespace IdentityServices.IntegrationTests.Helpers;

/// <summary>
///     AB#8997: lets an HTTP test arrange the lifecycle record identity reads for the <c>tenant_gen</c> claim, without
///     writing a record into the shared system database (in the test host the system tenant has no record, so the golden
///     token shapes carry no claim). <see cref="GetAsync" /> answers an arranged record, an arranged failure or — for every tenant without
///     an arrangement — the production store. Every other member passes through unchanged. One factory per test class,
///     so an arrangement is visible to that class only; tests reset it in <c>finally</c>.
/// </summary>
public sealed class TestTenantLifecycleStore
{
    private readonly ConcurrentDictionary<string, Func<TenantLifecycleRecord?>> _arranged =
        new(StringComparer.Ordinal);

    private readonly ConcurrentDictionary<string, int> _reads = new(StringComparer.Ordinal);

    /// <summary>Answers a record with <paramref name="createdUtc" /> for <paramref name="tenantId" />.</summary>
    public void ArrangeGeneration(string tenantId, DateTime createdUtc) =>
        _arranged[tenantId] = () => new TenantLifecycleRecord
        {
            TenantId = tenantId, CreatedUtc = createdUtc, State = TenantLifecycleState.Active
        };

    /// <summary>Answers "no record" for <paramref name="tenantId" />.</summary>
    public void ArrangeNoRecord(string tenantId) => _arranged[tenantId] = () => null;

    /// <summary>Throws <paramref name="exception" /> for every read of <paramref name="tenantId" />.</summary>
    public void ArrangeFailure(string tenantId, Exception exception) => _arranged[tenantId] = () => throw exception;

    /// <summary>Number of <see cref="ITenantLifecycleStore.GetAsync" /> calls for <paramref name="tenantId" />.</summary>
    public int ReadsOf(string tenantId) => _reads.TryGetValue(tenantId, out var count) ? count : 0;

    public void Reset()
    {
        _arranged.Clear();
        _reads.Clear();
    }

    public ITenantLifecycleStore Over(ITenantLifecycleStore production) => new Layered(this, production);

    private sealed class Layered(TestTenantLifecycleStore arranged, ITenantLifecycleStore production)
        : ITenantLifecycleStore
    {
        public Task<TenantLifecycleRecord?> GetAsync(string tenantId, CancellationToken cancellationToken = default)
        {
            arranged._reads.AddOrUpdate(tenantId, 1, (_, count) => count + 1);
            return arranged._arranged.TryGetValue(tenantId, out var answer)
                ? Task.FromResult(answer())
                : production.GetAsync(tenantId, cancellationToken);
        }

        public Task<IReadOnlyList<TenantLifecycleRecord>> ListAsync(CancellationToken cancellationToken = default) =>
            production.ListAsync(cancellationToken);

        public Task EnsureCreatingAsync(string tenantId, string? databaseName, Guid correlationId,
            CancellationToken cancellationToken = default) =>
            production.EnsureCreatingAsync(tenantId, databaseName, correlationId, cancellationToken);

        public Task SetPhaseAsync(string tenantId, TenantLifecyclePhase phase, string? lastError = null,
            CancellationToken cancellationToken = default) =>
            production.SetPhaseAsync(tenantId, phase, lastError, cancellationToken);

        public Task MarkActiveAsync(string tenantId, string? databaseName = null,
            CancellationToken cancellationToken = default) =>
            production.MarkActiveAsync(tenantId, databaseName, cancellationToken);

        public Task MarkFailedAsync(string tenantId, string error, CancellationToken cancellationToken = default) =>
            production.MarkFailedAsync(tenantId, error, cancellationToken);

        public Task MarkDeletingAsync(string tenantId, CancellationToken cancellationToken = default) =>
            production.MarkDeletingAsync(tenantId, cancellationToken);

        public Task EnsureDeletingAsync(string tenantId, string? databaseName, Guid correlationId,
            CancellationToken cancellationToken = default) =>
            production.EnsureDeletingAsync(tenantId, databaseName, correlationId, cancellationToken);

        public Task EnsureDeletingAsync(string tenantId, string? databaseName, Guid correlationId,
            TenantOwnershipMarkerIdentity? overriddenForeignMarker, CancellationToken cancellationToken = default) =>
            production.EnsureDeletingAsync(tenantId, databaseName, correlationId, overriddenForeignMarker,
                cancellationToken);

        public Task RemoveAsync(string tenantId, CancellationToken cancellationToken = default) =>
            production.RemoveAsync(tenantId, cancellationToken);

        public Task<TenantLifecycleRecord?> TryClaimForReconcileAsync(string leaseOwner, TimeSpan leaseDuration,
            CancellationToken cancellationToken = default) =>
            production.TryClaimForReconcileAsync(leaseOwner, leaseDuration, cancellationToken);

        public Task<TenantLifecycleRecord?> TryClaimForReconcileAsync(string leaseOwner, TimeSpan leaseDuration,
            TimeSpan? minimumAge, CancellationToken cancellationToken = default) =>
            production.TryClaimForReconcileAsync(leaseOwner, leaseDuration, minimumAge, cancellationToken);

        public Task ReleaseLeaseAsync(string tenantId, string leaseOwner,
            CancellationToken cancellationToken = default) =>
            production.ReleaseLeaseAsync(tenantId, leaseOwner, cancellationToken);

        public Task<TenantLifecycleRecord?> RequeueForReconcileAsync(string tenantId,
            CancellationToken cancellationToken = default) =>
            production.RequeueForReconcileAsync(tenantId, cancellationToken);
    }
}
