namespace IdentityServerPersistence.Services.SourceTenantGrants;

/// <summary>
///     Decides whether a source tenant S permits a target tenant T to look up and grant access to S's users when S is
///     <b>not</b> a registry ancestor of T (Feature AB#8313, <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §6).
/// </summary>
/// <remarks>
///     Registry ancestors are admitted by the callers through <see cref="ICrossTenantAncestryGuard" /> and never reach
///     this policy's decision. The shipped implementation is <see cref="AllowListSourceTenantGrantPolicy" /> (AB#8345): the
///     allow-list kept in S, empty by default.
/// </remarks>
public interface ISourceTenantGrantPolicy
{
    /// <summary>
    ///     <c>true</c> when <paramref name="sourceTenantId" /> permits <paramref name="targetTenantId" />. Must not throw
    ///     for an unknown source tenant (answer <c>false</c>) and must not reveal anything to the caller.
    /// </summary>
    Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId, CancellationToken cancellationToken = default);
}

/// <summary>
///     No tenant permits any other tenant. Together with the registry check of the callers this is "deny every
///     non-ancestor" — a sibling lookup answers the uniform <c>404</c>. The shipped default until AB#8345; kept for tests
///     and as the behaviour every tenant has with an empty allow-list.
/// </summary>
public sealed class DenyNonAncestorsSourceTenantGrantPolicy : ISourceTenantGrantPolicy
{
    /// <inheritdoc />
    public Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId,
        CancellationToken cancellationToken = default) => Task.FromResult(false);
}
