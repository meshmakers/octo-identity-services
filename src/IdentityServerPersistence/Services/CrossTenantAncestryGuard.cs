using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityServerPersistence.Services;

/// <summary>How a claimed cross-tenant ancestor that the tenant registry does not confirm is treated (AB#8339).</summary>
public enum CrossTenantAncestryMode
{
    /// <summary>
    ///     The claim is let through as before AB#8339, and every such use is logged as a warning ("would be denied").
    ///     The default, so existing setups keep working until the per-cluster inventory is reviewed.
    /// </summary>
    Warn = 0,

    /// <summary>Only a registry ancestor counts; the claim is refused.</summary>
    Enforce = 1
}

/// <summary>
///     Options of the cross-tenant ancestry check (AB#8339), bound from the <c>"IdentityApiAuthorization"</c>
///     configuration section, i.e. <c>OCTO_IDENTITYAPIAUTHORIZATION__CROSSTENANTANCESTRY=Warn|Enforce</c>. Shares the
///     section with the identity REST API authorization options; only this key is read here.
/// </summary>
public class CrossTenantAncestryOptions
{
    /// <summary>The configuration section name.</summary>
    public const string SectionName = "IdentityApiAuthorization";

    /// <summary>Gets or sets the mode. Default <see cref="CrossTenantAncestryMode.Warn" />.</summary>
    public CrossTenantAncestryMode CrossTenantAncestry { get; set; } = CrossTenantAncestryMode.Warn;
}

/// <summary>
///     Decides whether one tenant is an ancestor of another — the implicit trust of the cross-tenant features (parent
///     login, token exchange, provisioning source users) — from the tenant registry, not from the identity providers a
///     tenant's own administrator can write (AB#8339).
/// </summary>
public interface ICrossTenantAncestryGuard
{
    /// <summary>The configured mode.</summary>
    CrossTenantAncestryMode Mode { get; }

    /// <summary>
    ///     The registry ancestors of <paramref name="tenantId" />, nearest first, ending with the system tenant. Empty
    ///     for the system tenant and for a tenant that is not registered.
    /// </summary>
    Task<IReadOnlyList<string>> GetRegistryAncestorsAsync(string tenantId);

    /// <summary>
    ///     Whether <paramref name="claimedAncestorTenantId" /> may be trusted as an ancestor of
    ///     <paramref name="tenantId" />: <c>true</c> when the registry confirms it. Otherwise a structured warning is
    ///     logged with both tenant ids and <paramref name="operation" />, and the result is <c>true</c> only in
    ///     <see cref="CrossTenantAncestryMode.Warn" />.
    /// </summary>
    Task<bool> IsTrustedAncestorAsync(string tenantId, string claimedAncestorTenantId, string operation);

    /// <summary>
    ///     Like <see cref="IsTrustedAncestorAsync" /> against an ancestor list the caller already read with
    ///     <see cref="GetRegistryAncestorsAsync" /> (no registry read).
    /// </summary>
    bool IsTrustedAncestor(string tenantId, IReadOnlyList<string> registryAncestors, string claimedAncestorTenantId,
        string operation);
}

/// <inheritdoc />
/// <remarks>
///     <para>
///         The registry is the platform-wide tenant list of the system database (<c>RtEntity_SystemTenant</c>), each
///         row stamped with its logical parent (AB#5311) — the same source the subtree walk of discovery and topology
///         uses (<see cref="TenantSubtreeWalker" />, AB#6759). A row without a parent id is a direct child of the
///         system tenant (as in <c>ScratchTenantGrantService</c>). The rows come from the shared
///         <see cref="ITenantRegistry" /> snapshot (AB#6393: one registry read per request, not per hop); a tenant
///         missing from the snapshot triggers its miss refresh, so a tenant created a moment ago finds its parents.
///     </para>
///     <para>
///         A read error yields no ancestors — fail closed under <see cref="CrossTenantAncestryMode.Enforce" />, logged
///         and let through under <see cref="CrossTenantAncestryMode.Warn" />. A cycle in a hand-edited registry ends
///         the walk.
///     </para>
/// </remarks>
public sealed class CrossTenantAncestryGuard(
    ITenantRegistry tenantRegistry,
    ISystemContext systemContext,
    IOptionsMonitor<CrossTenantAncestryOptions> options,
    ILogger<CrossTenantAncestryGuard> logger) : ICrossTenantAncestryGuard
{
    /// <inheritdoc />
    public CrossTenantAncestryMode Mode => options.CurrentValue.CrossTenantAncestry;

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetRegistryAncestorsAsync(string tenantId)
    {
        var systemTenantId = systemContext.TenantId;
        if (string.IsNullOrWhiteSpace(tenantId) ||
            string.Equals(tenantId, systemTenantId, StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        var ancestors = new List<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { tenantId };
        var current = tenantId;
        try
        {
            while (await tenantRegistry.TryGetTenantAsync(current) is { } tenant)
            {
                var next = string.IsNullOrEmpty(tenant.ParentTenantId) ? systemTenantId : tenant.ParentTenantId;
                if (!visited.Add(next))
                {
                    break;
                }

                ancestors.Add(next);
                if (string.Equals(next, systemTenantId, StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                current = next;
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Cross-tenant ancestry: the tenant registry could not be read for tenant {TenantId}; no ancestor is confirmed (AB#8339)",
                tenantId);
            return [];
        }

        return ancestors;
    }
    /// <inheritdoc />
    public async Task<bool> IsTrustedAncestorAsync(string tenantId, string claimedAncestorTenantId, string operation)
        => IsTrustedAncestor(tenantId, await GetRegistryAncestorsAsync(tenantId), claimedAncestorTenantId, operation);

    /// <inheritdoc />
    public bool IsTrustedAncestor(string tenantId, IReadOnlyList<string> registryAncestors,
        string claimedAncestorTenantId, string operation)
    {
        if (registryAncestors.Contains(claimedAncestorTenantId, StringComparer.OrdinalIgnoreCase))
        {
            return true;
        }

        if (Mode == CrossTenantAncestryMode.Warn)
        {
            logger.LogWarning(
                "Cross-tenant ancestry not confirmed by the tenant registry, allowed by CrossTenantAncestry=Warn: {ClaimedAncestorTenantId} is not an ancestor of {TenantId} ({Operation}). " +
                "This would be denied with CrossTenantAncestry=Enforce (AB#8339)",
                claimedAncestorTenantId, tenantId, operation);
            return true;
        }

        logger.LogWarning(
            "Cross-tenant ancestry denied: {ClaimedAncestorTenantId} is not an ancestor of {TenantId} in the tenant registry ({Operation}) (AB#8339)",
            claimedAncestorTenantId, tenantId, operation);
        return false;
    }
}
