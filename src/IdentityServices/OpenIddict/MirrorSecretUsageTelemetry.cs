using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Records <b>which</b> secret a mirrored client authenticated with — the one it inherited from
///     its parent tenant, or the one that belongs to that mirror alone (AB#5065, step 3 of
///     <c>docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md</c>).
/// </summary>
public interface IMirrorSecretUsageTelemetry
{
    /// <summary>
    ///     Called by <see cref="OctoApplicationManager" /> once a presented client secret has been
    ///     matched against a stored record. Never throws — a failed measurement must not decide an
    ///     authentication.
    /// </summary>
    /// <param name="application">The client that authenticated.</param>
    /// <param name="storedSecrets">All stored secret records of that client.</param>
    /// <param name="matchedSecret">The record the presented credential matched.</param>
    void RecordSecretMatch(RtClient application, IReadOnlyList<RtSecretRecord> storedSecrets,
        RtSecretRecord matchedSecret);
}

/// <summary>
///     Log-only implementation of <see cref="IMirrorSecretUsageTelemetry" /> (AB#5065).
/// </summary>
/// <remarks>
///     <para>
///         <b>Why this exists.</b> AB#5061 gave every mirror of a confidential parent its own
///         generated secret but deliberately kept copying the inherited one, because live fleet
///         credentials (<c>ci-deploy</c>, <c>octo-ai-adapter</c>, <c>claude-agent</c>) still
///         authenticate with the parent's secret against child tenants. While that copy is accepted,
///         a child credential is still a parent credential and the escalation is open. Removing it
///         (step 4) is only defensible once it is <i>known</i> that nobody uses it any more — and
///         nothing in the service could tell the two apart. This is that measurement, and it is the
///         only thing standing between step 2 and step 4.
///     </para>
///     <para>
///         <b>Where it hangs — and why it moved.</b> Before the OpenIddict migration this was a
///         decorator around Duende's <c>ISecretsListValidator</c>, the one place where the presented
///         credential and the client's whole secret list were both in hand. OpenIddict has no such
///         service: client authentication goes through
///         <c>OpenIddictApplicationManager.ValidateClientSecretAsync</c>, so
///         <see cref="OctoApplicationManager" /> is now that place — it already owns the comparison
///         (legacy hash format) and it is the only code that knows <i>which</i> stored record
///         matched. The decision itself is still not made here: this type is called after the match
///         and only writes a log record.
///     </para>
///     <para>
///         🔴 <b>Cost — this is the authentication hot path for every client.</b> The classification
///         reads only what the manager already had in hand and never queries a store. A client that
///         holds no own secret at all — every ordinary client, every public mirror — leaves after a
///         single string comparison per stored record (there are at most two).
///     </para>
///     <para>
///         🔴 <b>No secret material is ever logged</b> — not the credential, not the stored hash, not
///         a prefix of either. The only values written are the client id, the tenant and the literal
///         string <c>own</c> or <c>inherited</c>. Pinned against the <i>rendered</i> log output
///         rather than against the format strings.
///     </para>
///     <para>
///         <b>Blind spot, and why it is acceptable.</b> Mirror-ness is inferred from the presence of
///         an own secret, because the alternative — reading <c>ProvisionedByParentTenantId</c> from a
///         freshly loaded record — would be a database round trip on every token request. A mirror
///         that has no own secret yet (public parent, or a confidential one whose provisioning loop
///         has not run since AB#5061 shipped) is invisible here. That is precisely the state step 4
///         must not be executed in anyway, so this being silent for such a client is a missing
///         precondition, not a false clean bill of health.
///     </para>
///     <para>
///         <b>Reading the result.</b> Every record renders the literal token <c>MirrorSecretUsage</c>
///         and the field <c>secretKind</c>, so per environment:
///         <c>{namespace="octo", container="identity"} |= "MirrorSecretUsage" |= "secretKind=inherited"</c>
///         answers "does anybody still authenticate with the inherited secret?", and grouping the
///         same query by <c>clientId</c> / <c>tenantId</c> names who and where. Inherited use is
///         logged at <b>Warning</b> and own use at Information: the inherited count is the number
///         that has to reach zero.
///     </para>
///     <para>
///         <b>Log-only, deliberately.</b> The AB#5058 refusal next door persists an audit entry
///         through <see cref="IIdentityAuditService" />, but that fires on a rejected request. This
///         one fires on <i>every successful</i> authentication of the affected clients, and a
///         runtime-event-log write per token request is exactly the hot-path cost this design is
///         avoiding. The question it answers — "is the count zero for a whole release?" — is a
///         log-aggregation question anyway.
///     </para>
///     <para>
///         <b>One guard became structural.</b> The Duende decorator had to exclude credentials that
///         are not shared secrets (private key JWT, mTLS) — without that they would have been
///         counted as inherited use and would have blocked step 4 forever.
///         <c>ValidateClientSecretAsync</c> is by definition the shared-secret path, so under
///         OpenIddict no such credential ever reaches this code.
///     </para>
/// </remarks>
internal sealed class MirrorSecretUsageTelemetry(
    IHttpContextAccessor httpContextAccessor,
    ILogger<MirrorSecretUsageTelemetry> logger) : IMirrorSecretUsageTelemetry
{
    /// <summary>Value of the <c>secretKind</c> field for the mirror's own, tenant-scoped secret.</summary>
    internal const string OwnSecretKind = "own";

    /// <summary>
    ///     Value of the <c>secretKind</c> field for the copy inherited from the parent tenant — the
    ///     one whose usage count has to reach zero before it can be removed (step 4).
    /// </summary>
    internal const string InheritedSecretKind = "inherited";

    /// <summary>
    ///     Stands in for the tenant when the request did not resolve to one. On the
    ///     <c>client_credentials</c> path that means no <c>acr_values</c> was sent, which AB#5058
    ///     refuses a few steps later for exactly the mirrored clients seen here — so this value
    ///     marks a request that is about to be rejected, not a successfully addressed tenant.
    /// </summary>
    internal const string UnresolvedTenantId = "(unresolved)";

    /// <summary>
    ///     Stable identifier of the measurement record, in the same 506xx band as the other AB#50xx
    ///     identity events.
    /// </summary>
    internal static readonly EventId MirrorSecretUsageEventId = new(50650, "MirrorSecretUsage");

    public void RecordSecretMatch(RtClient application, IReadOnlyList<RtSecretRecord> storedSecrets,
        RtSecretRecord matchedSecret)
    {
        try
        {
            // Nothing to tell apart unless this client actually holds an own secret — i.e. unless it
            // is a mirror provisioned since AB#5061.
            if (!HoldsOwnSecret(storedSecrets))
            {
                return;
            }

            var isOwn = ClientMirrorSecrets.IsOwnSecret(matchedSecret);
            var tenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
            if (string.IsNullOrEmpty(tenantId))
            {
                tenantId = UnresolvedTenantId;
            }

            logger.Log(
                isOwn ? LogLevel.Information : LogLevel.Warning,
                MirrorSecretUsageEventId,
                "MirrorSecretUsage secretKind={MirrorSecretKind} clientId={ClientId} tenantId={TenantId} " +
                "— a mirrored client authenticated with this secret (AB#5065)",
                isOwn ? OwnSecretKind : InheritedSecretKind, application.ClientId, tenantId);
        }
        catch (Exception ex)
        {
            // Telemetry must never decide an authentication. A caller that authenticated correctly
            // stays authenticated even if the measurement fails; the gap shows up as this error,
            // which is itself a reason not to trust a zero count for that period.
            logger.LogError(ex,
                "MirrorSecretUsage measurement failed for client '{ClientId}'; the authentication " +
                "itself is unaffected (AB#5065)", application.ClientId);
        }
    }

    /// <summary>
    ///     True when the list carries the mirror-own marker. Indexed rather than enumerated so the
    ///     ordinary client — the overwhelming majority of every token request — does not even
    ///     allocate an enumerator.
    /// </summary>
    private static bool HoldsOwnSecret(IReadOnlyList<RtSecretRecord> secrets)
    {
        for (var i = 0; i < secrets.Count; i++)
        {
            if (ClientMirrorSecrets.IsOwnSecret(secrets[i]))
            {
                return true;
            }
        }

        return false;
    }
}
