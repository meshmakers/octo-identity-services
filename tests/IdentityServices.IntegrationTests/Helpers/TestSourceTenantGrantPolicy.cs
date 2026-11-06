using System.Collections.Concurrent;
using IdentityServerPersistence.Services.SourceTenantGrants;

namespace IdentityServices.IntegrationTests.Helpers;

/// <summary>
///     AB#8341: the grant policy of the HTTP test host. A test permits exactly the (source, target) pairs it arranged —
///     tenant ids carry a GUID suffix, so pairs of parallel tests never meet; every other pair is decided by the shipped
///     default <see cref="DenyNonAncestorsSourceTenantGrantPolicy" />, so an unpermitted sibling behaves as in production
///     until AB#8345.
/// </summary>
public sealed class TestSourceTenantGrantPolicy : ISourceTenantGrantPolicy
{
    private readonly ConcurrentDictionary<(string Source, string Target), bool> _permitted = new();
    private readonly DenyNonAncestorsSourceTenantGrantPolicy _default = new();

    /// <summary>Lets <paramref name="sourceTenantId" /> permit <paramref name="targetTenantId" />.</summary>
    public void Permit(string sourceTenantId, string targetTenantId)
        => _permitted[(sourceTenantId.ToLowerInvariant(), targetTenantId.ToLowerInvariant())] = true;

    /// <inheritdoc />
    public Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId,
        CancellationToken cancellationToken = default)
        => _permitted.ContainsKey((sourceTenantId.ToLowerInvariant(), targetTenantId.ToLowerInvariant()))
            ? Task.FromResult(true)
            : _default.IsPermittedAsync(sourceTenantId, targetTenantId, cancellationToken);
}
