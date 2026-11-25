using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services.ServiceAccountExchange;

/// <summary>Registry relation of the target tenant U to the source tenant T of a service-account exchange.</summary>
public enum ServiceAccountExchangeRelation
{
    /// <summary>U is the registry parent of T.</summary>
    Parent,

    /// <summary>U and T are registry children of the same parent, which is not the system tenant.</summary>
    Sibling,

    /// <summary>U is a registry child of T.</summary>
    Child
}

/// <summary>Why the gate refused a service-account exchange.</summary>
public enum ServiceAccountExchangeRefusal
{
    /// <summary>Admitted.</summary>
    None,

    /// <summary>T or U is the system tenant.</summary>
    SystemTenant,

    /// <summary>T and U are the same tenant.</summary>
    SameTenant,

    /// <summary>T or U is not in the tenant registry.</summary>
    UnknownTenant,

    /// <summary>U is neither parent, sibling nor child of T (e.g. a grandchild, a cousin, an unrelated tenant).</summary>
    NotRelated,

    /// <summary>The subject client does not exist in T or is disabled.</summary>
    SourceClientUnknown,

    /// <summary>The subject client is a mirror source or a mirror: its secret is shared across tenants.</summary>
    MirroredClient,

    /// <summary>The subject client is itself a shadow client (<c>xt_</c>), or its shadow name is ambiguous.</summary>
    AmbiguousSubject,

    /// <summary>U holds no enabled shadow client of its own with at least one role.</summary>
    NotProvisioned,

    /// <summary>
    ///     U's shadow client can do more than the exchange: another grant type than token-exchange, redirect URIs,
    ///     offline access or a secret. It must be a public client that can only present an exchange.
    /// </summary>
    ShadowClientNotExchangeOnly,

    /// <summary>U is T's parent or sibling and T's allow-list does not permit U.</summary>
    NotPermitted,

    /// <summary>The state needed for the decision could not be read (fail closed).</summary>
    StateUnreadable
}

/// <summary>Decision of <see cref="IServiceAccountExchangeGate" />.</summary>
public sealed record ServiceAccountExchangeDecision
{
    public ServiceAccountExchangeRefusal Refusal { get; init; }

    /// <summary>Non-sensitive reason for logs and audit; never contains a secret or a token.</summary>
    public string Reason { get; init; } = string.Empty;

    public ServiceAccountExchangeRelation? Relation { get; init; }

    /// <summary>The shadow client in U (<c>xt_{T}_{clientId}</c>), when admitted.</summary>
    public RtClient? ShadowClient { get; init; }

    /// <summary>The effective role names of the shadow client in U, when admitted (never empty then).</summary>
    public IReadOnlySet<string> RoleNames { get; init; } = new HashSet<string>();

    public bool IsAdmitted => Refusal == ServiceAccountExchangeRefusal.None;

    public static ServiceAccountExchangeDecision Refused(ServiceAccountExchangeRefusal refusal, string reason,
        ServiceAccountExchangeRelation? relation = null) =>
        new() { Refusal = refusal, Reason = reason, Relation = relation };
}

/// <summary>
///     The authorization of an RFC 8693 exchange whose subject is a service account (client-credentials token) of tenant
///     T, into tenant U, presented by U's shadow client. Protocol-free: the subject token is validated by
///     the caller; this gate decides on registry and directory state only.
/// </summary>
public interface IServiceAccountExchangeGate
{
    /// <summary>Decides whether the service account <paramref name="sourceClientId" /> of T may act in U.</summary>
    Task<ServiceAccountExchangeDecision> EvaluateAsync(string sourceTenantId, string sourceClientId,
        string targetTenantId);
}

/// <inheritdoc />
/// <remarks>
///     <para>
///         <b>Invariant.</b> A service account of T obtains a token for U only when (1) U is T's registry parent, sibling
///         (same parent, not the system tenant) or child, (2) neither is the system tenant, (3) the account is an enabled,
///         unmirrored client of T, (4) U's administrator provisioned it in U: an enabled client
///         <c>xt_{T}_{clientId}</c> of U's own (no mirror) with at least one effective role (direct or through groups),
///         that can do nothing but present the exchange (public, the token-exchange grant only, no redirect URIs, no
///         offline access), and (5) for a parent or sibling U, T's allow-list permits U (<see cref="ISourceTenantGrantPolicy" />, the rule
///         sibling grants of users follow). The roles of the issued token are exactly the shadow client's roles in
///         U; no role of T is read. Every unreadable state refuses.
///     </para>
///     <para>
///         <b>Mirrors are refused</b> (<c>docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md</c> §1): a mirrored client shares its
///         secret with other tenants, so its token of T proves nothing about T.
///     </para>
///     <para>
///         <b>Names are unambiguous or refused.</b> Tenant ids may contain <c>_</c>, so
///         <c>xt_{T}_{clientId}</c> could also be read with another registered tenant id as prefix; such a name is refused,
///         as is a subject that is itself a shadow client (no chains in v1).
///     </para>
/// </remarks>
public sealed class ServiceAccountExchangeGate(
    ISystemContext systemContext,
    ITenantRegistry tenantRegistry,
    ISourceTenantGrantPolicy grantPolicy,
    IClientMirrorProvisioningService clientMirrorProvisioningService,
    ICrossTenantShadowUserChainResolver shadowUserChainResolver,
    ILogger<ServiceAccountExchangeGate> logger) : IServiceAccountExchangeGate
{
    /// <inheritdoc />
    public async Task<ServiceAccountExchangeDecision> EvaluateAsync(string sourceTenantId, string sourceClientId,
        string targetTenantId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceTenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetTenantId);

        try
        {
            return await EvaluateCoreAsync(sourceTenantId, sourceClientId, targetTenantId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Service-account exchange refused: the state for client '{ClientId}' of '{SourceTenantId}' into '{TargetTenantId}' could not be read",
                sourceClientId, sourceTenantId, targetTenantId);
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.StateUnreadable,
                "state could not be read");
        }
    }

    private async Task<ServiceAccountExchangeDecision> EvaluateCoreAsync(string sourceTenantId,
        string sourceClientId, string targetTenantId)
    {
        var systemTenantId = systemContext.TenantId;
        if (string.IsNullOrEmpty(systemTenantId) || IsSame(sourceTenantId, systemTenantId) ||
            IsSame(targetTenantId, systemTenantId))
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.SystemTenant,
                "the system tenant is neither source nor target of a service-account exchange");
        }

        if (IsSame(sourceTenantId, targetTenantId))
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.SameTenant,
                "source and target tenant are the same");
        }

        var source = await tenantRegistry.TryGetTenantAsync(sourceTenantId);
        var target = await tenantRegistry.TryGetTenantAsync(targetTenantId);
        if (source == null || target == null)
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.UnknownTenant,
                "source or target tenant is not registered");
        }

        var relation = DetermineRelation(source, target, systemTenantId);
        if (relation == null)
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.NotRelated,
                "the target tenant is neither parent, sibling nor child of the source tenant");
        }

        if (CrossTenantShadowUserName.IsShadowUserName(sourceClientId))
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.AmbiguousSubject,
                "the subject client is itself a shadow client", relation);
        }

        var sourceRepository = await tenantRegistry.TryGetRepositoryAsync(source.TenantId);
        var sourceClient = sourceRepository == null ? null : await FindClientAsync(sourceRepository, sourceClientId);
        if (sourceClient is not { Enabled: true })
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.SourceClientUnknown,
                "the subject client does not exist in the source tenant or is disabled", relation);
        }

        if (sourceClient.AutoProvisionInChildTenants ||
            !string.IsNullOrEmpty(sourceClient.ProvisionedByParentTenantId) ||
            (await clientMirrorProvisioningService.GetMirrorsAsync(source.TenantId, sourceClientId)).Count > 0)
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.MirroredClient,
                "the subject client is mirrored; its secret is shared with other tenants", relation);
        }

        if (await FindOtherTenantPrefixAsync(source.TenantId, sourceClientId) is { } otherTenantId)
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.AmbiguousSubject,
                $"the shadow client name is ambiguous: it also reads as a client of tenant '{otherTenantId}'", relation);
        }

        // The exact name of the verified subject (tenant id as in its token), compared case-sensitively.
        var shadowClientId = CrossTenantShadowUserName.Build(sourceTenantId, sourceClientId);
        var targetRepository = await tenantRegistry.TryGetRepositoryAsync(target.TenantId);
        if (targetRepository == null)
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.UnknownTenant,
                "target tenant is not registered", relation);
        }

        var shadowClient = await FindClientAsync(targetRepository, shadowClientId);
        if (shadowClient is not { Enabled: true } || shadowClient.AutoProvisionInChildTenants ||
            !string.IsNullOrEmpty(shadowClient.ProvisionedByParentTenantId))
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.NotProvisioned,
                "the target tenant holds no enabled shadow client of its own", relation);
        }

        if (DescribeNonExchangeCapability(shadowClient) is { } capability)
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.ShadowClientNotExchangeOnly,
                $"the shadow client may only present the token exchange, but it {capability}", relation);
        }

        var roleNames = await ResolveRoleNamesAsync(targetRepository, shadowClient);
        if (roleNames.Count == 0)
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.NotProvisioned,
                "the shadow client holds no role in the target tenant", relation);
        }

        // Parent and sibling are no registry descendants of T: T must permit U, as for sibling grants of users.
        if (relation != ServiceAccountExchangeRelation.Child &&
            !await grantPolicy.IsPermittedAsync(source.TenantId, target.TenantId))
        {
            return ServiceAccountExchangeDecision.Refused(ServiceAccountExchangeRefusal.NotPermitted,
                "the source tenant does not permit the target tenant", relation);
        }

        return new ServiceAccountExchangeDecision
        {
            Refusal = ServiceAccountExchangeRefusal.None,
            Relation = relation,
            ShadowClient = shadowClient,
            RoleNames = roleNames
        };
    }

    /// <summary>Parent, sibling or child from the registry parents; <c>null</c> for any other relation.</summary>
    internal static ServiceAccountExchangeRelation? DetermineRelation(OctoTenant source, OctoTenant target,
        string systemTenantId)
    {
        var sourceParent = NormalizeParent(source.ParentTenantId, systemTenantId);
        var targetParent = NormalizeParent(target.ParentTenantId, systemTenantId);

        if (IsSame(targetParent, source.TenantId))
        {
            return ServiceAccountExchangeRelation.Child;
        }

        if (IsSame(sourceParent, target.TenantId))
        {
            return ServiceAccountExchangeRelation.Parent;
        }

        // Top-level tenants (children of the system tenant) are unrelated customers, not siblings.
        return !IsSame(sourceParent, systemTenantId) && IsSame(sourceParent, targetParent)
            ? ServiceAccountExchangeRelation.Sibling
            : null;
    }

    /// <summary>The grant type URN the shadow client must carry, and the only one.</summary>
    public const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>
    ///     What lets the shadow client act on its own besides presenting an exchange, or <c>null</c>: a shadow client that
    ///     could obtain tokens itself (another grant, a secret, offline access) or redirect a browser is refused.
    /// </summary>
    internal static string? DescribeNonExchangeCapability(RtClient client)
    {
        var grantTypes = client.AllowedGrantTypes?.ToList() ?? [];
        if (grantTypes.Count != 1 || !string.Equals(grantTypes[0], TokenExchangeGrantType, StringComparison.Ordinal))
        {
            return "allows the grant types [" + string.Join(", ", grantTypes) + "]";
        }

        if (client.RedirectUris?.Any() == true || client.PostLogoutRedirectUris?.Any() == true)
        {
            return "has redirect URIs";
        }

        if (client.AllowOfflineAccess)
        {
            return "allows offline access";
        }

        if (client.RequireClientSecret || client.ClientSecrets?.Any() == true)
        {
            return "is a confidential client";
        }

        return null;
    }

    private static string NormalizeParent(string? parentTenantId, string systemTenantId)
        => string.IsNullOrEmpty(parentTenantId) ? systemTenantId : parentTenantId;

    private static bool IsSame(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    ///     Another registered tenant id that <c>{T}_{clientId}</c> could be split at, or <c>null</c> (the rule for
    ///     shadow names: an ambiguous name grants nothing).
    /// </summary>
    private async Task<string?> FindOtherTenantPrefixAsync(string sourceTenantId, string sourceClientId)
    {
        var joined = $"{sourceTenantId}_{sourceClientId}";
        // Every '_' after position 0 is a split point; a tenant id may itself start with '_' (an empty prefix is none).
        for (var index = joined.IndexOf('_', 1); index > 0; index = joined.IndexOf('_', index + 1))
        {
            var candidate = joined[..index];
            if (!IsSame(candidate, sourceTenantId) && await tenantRegistry.TryGetTenantAsync(candidate) != null)
            {
                return candidate;
            }
        }

        return null;
    }

    private static async Task<RtClient?> FindClientAsync(ITenantRepository repository, string clientId)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        await session.CommitTransactionAsync();

        // A client id is unique in a directory; more than one match is a broken directory: refuse.
        var clients = result.Items.Take(2).ToList();
        return clients.Count == 1 ? clients[0] : null;
    }

    private async Task<IReadOnlySet<string>> ResolveRoleNamesAsync(ITenantRepository repository, RtClient client)
    {
        var resolver = new FixedTenantRepositoryResolver(repository);
        var roleStore = new ClientRoleStore(resolver,
            new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver),
                shadowUserChainResolver),
            NullLogger<ClientRoleStore>.Instance);
        return await roleStore.GetEffectiveRoleNamesAsync(client.RtId);
    }
}
