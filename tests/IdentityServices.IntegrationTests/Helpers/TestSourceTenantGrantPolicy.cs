using System.Collections.Concurrent;
using IdentityServerPersistence.Services.SourceTenantGrants;

namespace IdentityServices.IntegrationTests.Helpers;

/// <summary>
///     AB#8341: the grant policy of the HTTP test host. A test permits exactly the (source, target) pairs it arranged —
///     tenant ids carry a GUID suffix, so pairs of parallel tests never meet. Every other pair is decided by the
///     production policy the host passes to <see cref="Over" /> (AB#8345: the allow-list kept in the source tenant, empty
///     by default), so an unarranged sibling behaves as in production.
/// </summary>
public sealed class TestSourceTenantGrantPolicy : ISourceTenantGrantPolicy
{
    private readonly ConcurrentDictionary<(string Source, string Target), bool> _permitted = new();
    private readonly DenyNonAncestorsSourceTenantGrantPolicy _default = new();

    /// <summary>Lets <paramref name="sourceTenantId" /> permit <paramref name="targetTenantId" />.</summary>
    public void Permit(string sourceTenantId, string targetTenantId)
        => _permitted[(sourceTenantId.ToLowerInvariant(), targetTenantId.ToLowerInvariant())] = true;

    /// <summary>The arranged pairs on top of <paramref name="production" /> (one instance per request scope).</summary>
    public ISourceTenantGrantPolicy Over(ISourceTenantGrantPolicy production) => new Layered(this, production);

    /// <inheritdoc />
    public Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId,
        CancellationToken cancellationToken = default)
        => IsArranged(sourceTenantId, targetTenantId)
            ? Task.FromResult(true)
            : _default.IsPermittedAsync(sourceTenantId, targetTenantId, cancellationToken);

    private bool IsArranged(string sourceTenantId, string targetTenantId)
        => _permitted.ContainsKey((sourceTenantId.ToLowerInvariant(), targetTenantId.ToLowerInvariant()));

    private sealed class Layered(TestSourceTenantGrantPolicy arranged, ISourceTenantGrantPolicy production)
        : ISourceTenantGrantPolicy
    {
        public Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId,
            CancellationToken cancellationToken = default)
            => arranged.IsArranged(sourceTenantId, targetTenantId)
                ? Task.FromResult(true)
                : production.IsPermittedAsync(sourceTenantId, targetTenantId, cancellationToken);
    }
}
