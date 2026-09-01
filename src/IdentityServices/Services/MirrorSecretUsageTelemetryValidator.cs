using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Services.Infrastructure;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Records <b>which</b> secret a mirrored client authenticated with — the one it inherited from
///     its parent tenant, or the one that belongs to that mirror alone (AB#5065, step 3 of
///     <c>docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md</c>).
/// </summary>
/// <remarks>
///     <para>
///         <b>Why this exists.</b> AB#5061 gave every mirror of a confidential parent its own
///         generated secret but deliberately kept copying the inherited one, because live fleet
///         credentials (<c>ci-deploy</c>, <c>octo-ai-adapter</c>, <c>claude-agent</c>) still
///         authenticate with the parent's secret against child tenants. While that copy is accepted,
///         a child credential is still a parent credential and the escalation is open. Removing it
///         (step 4) is only defensible once it is <i>known</i> that nobody uses it any more — and
///         nothing in the service could tell the two apart. This validator is that measurement, and
///         it is the only thing standing between step 2 and step 4.
///     </para>
///     <para>
///         <b>Where it hangs.</b> Duende resolves a single <see cref="ISecretsListValidator" /> and
///         calls it from <c>ClientSecretValidator</c> (and <c>ApiSecretValidator</c>) with the
///         credential the caller presented and the secret list of the entity it claims to be. This
///         type <b>decorates</b> that service and <b>delegates every decision</b> to Duende's own
///         <see cref="SecretValidator" /> — constructed explicitly in <c>Program.cs</c> and injected
///         as the inner <see cref="ISecretsListValidator" />: the validation itself is untouched, no
///         secret is accepted or rejected that would not have been before, and a failed
///         authentication returns the inner result verbatim without so much as a log line. The individual
///         <see cref="ISecretValidator" /> chain is not replaced either — replacing it would have
///         meant reimplementing hashing, expiry and the X.509/private-key-JWT branches.
///     </para>
///     <para>
///         🔴 <b>Cost — this is the authentication hot path for every client.</b> The classification
///         therefore reads only what Duende already handed in and never queries a store:
///     </para>
///     <list type="number">
///         <item>
///             A failed validation returns immediately.
///         </item>
///         <item>
///             A credential that is not a shared secret (private key JWT, mTLS) returns immediately —
///             one reference comparison.
///         </item>
///         <item>
///             The mirror marker is <see cref="ClientMirrorSecrets.OwnSecretDescription" /> on the
///             secret record itself, which the AutoMapper <c>RtSecretRecord → Secret</c> map already
///             carries into the model Duende passes here. Deciding "is this a mirror with its own
///             secret" is therefore a walk over the ≤2 secrets that were passed in, comparing one
///             string each — indexed when the list allows it, so the ordinary client costs not even
///             an enumerator allocation.
///         </item>
///         <item>
///             Only a client that <i>has</i> an own secret pays for the classification: one more
///             call into the inner validator over the own-secret subset, i.e. a single SHA-256 over
///             the presented credential. Everything else — a normal client, a public mirror, an API
///             resource on the introspection endpoint — leaves through step 3 having allocated
///             nothing.
///         </item>
///     </list>
///     <para>
///         🔴 <b>No secret material is ever logged</b> — not the credential, not the stored hash, not
///         a prefix of either. The only values written are the client id, the tenant and the literal
///         string <c>own</c> or <c>inherited</c>. Pinned by
///         <c>MirrorSecretUsageTelemetryTests.NeverWritesSecretMaterialToTheLog</c>, which asserts
///         against the <i>rendered</i> log output rather than against the format strings.
///     </para>
///     <para>
///         <b>Blind spot, and why it is acceptable.</b> Mirror-ness is inferred from the presence of
///         an own secret, because the alternative — loading the <c>RtClient</c> to read
///         <c>ProvisionedByParentTenantId</c> — is a database round trip on every single token
///         request. A mirror that has no own secret yet (public parent, or a confidential one whose
///         provisioning loop has not run since AB#5061 shipped) is consequently invisible here. That
///         is precisely the state step 4 must not be executed in anyway: it is the same
///         precondition the migration table already carries — every mirror must hold its own secret
///         before the inherited one may be dropped — so this measurement being silent for such a
///         client is a missing precondition, not a false clean bill of health.
///     </para>
///     <para>
///         <b>Reading the result.</b> Every record renders the literal token
///         <c>MirrorSecretUsage</c> and the field <c>secretKind</c>, so per environment:
///         <c>{namespace="octo", container="identity"} |= "MirrorSecretUsage" |= "secretKind=inherited"</c>
///         answers "does anybody still authenticate with the inherited secret?", and grouping the
///         same query by <c>clientId</c> / <c>tenantId</c> names who and where. Inherited use is
///         logged at <b>Warning</b> and own use at Information: the inherited count is the number
///         that has to reach zero, and it stays low by construction — only confidential mirrored
///         clients reach this code at all.
///     </para>
///     <para>
///         <b>Log-only, deliberately.</b> The AB#5058 refusal next door persists a
///         <c>ClientCredentialsTenantAmbiguityEvent</c> through <c>OctoEventSink</c>, but that fires
///         on a rejected request. This one fires on <i>every successful</i> authentication of the
///         affected clients, and a runtime-event-log write per token request is exactly the hot-path
///         cost this design is avoiding. The question it answers — "is the count zero for a whole
///         release?" — is a log-aggregation question anyway.
///     </para>
/// </remarks>
public sealed class MirrorSecretUsageTelemetryValidator(
    ISecretsListValidator inner,
    IHttpContextAccessor httpContextAccessor,
    ILogger<MirrorSecretUsageTelemetryValidator> logger) : ISecretsListValidator
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

    public async Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets,
        ParsedSecret parsedSecret, CancellationToken cancellationToken = default)
    {
        // The validation itself, unchanged and unconditional.
        var result = await inner.ValidateAsync(secrets, parsedSecret, cancellationToken);

        // A rejected credential says nothing about which secret was meant, and the failure path must
        // stay exactly as noisy as it was before.
        if (!result.Success)
        {
            return result;
        }

        // Cheapest discriminator first: only a shared secret can be one of the two we tell apart.
        // A private-key JWT or an mTLS certificate would otherwise be misclassified as "inherited",
        // because the own-secret subset can never validate it.
        if (!string.Equals(parsedSecret.Type, IdentityServerConstants.ParsedSecretTypes.SharedSecret,
                StringComparison.Ordinal))
        {
            return result;
        }

        if (!ContainsOwnSecret(secrets))
        {
            return result;
        }

        try
        {
            await RecordSecretKindAsync(secrets, parsedSecret, cancellationToken);
        }
        catch (Exception ex)
        {
            // Telemetry must never decide an authentication. A caller that authenticated correctly
            // stays authenticated even if the measurement fails; the gap shows up as this error,
            // which is itself a reason not to trust a zero count for that period.
            logger.LogError(ex,
                "MirrorSecretUsage measurement failed for client '{ClientId}'; the authentication " +
                "itself is unaffected (AB#5065)", parsedSecret.Id);
        }

        return result;
    }

    /// <summary>
    ///     Re-validates the presented credential against the own-secret subset alone. Success means
    ///     the caller holds the mirror's tenant-scoped secret; failure means it matched one of the
    ///     remaining — inherited — entries, since the full list already validated.
    /// </summary>
    /// <remarks>
    ///     The inherited outcome makes Duende's own <see cref="SecretValidator" /> log its
    ///     "could not validate" line for the probe. That is at <c>Debug</c> under the
    ///     <c>Duende.IdentityServer.Validation.SecretValidator</c> category, so it does not surface
    ///     at production log levels and cannot be mistaken for a failed authentication — the
    ///     authentication itself already succeeded before this method is reached.
    /// </remarks>
    private async Task RecordSecretKindAsync(IEnumerable<Secret> secrets, ParsedSecret parsedSecret,
        CancellationToken cancellationToken)
    {
        var ownSecrets = new List<Secret>(1);
        foreach (var secret in secrets)
        {
            if (IsOwnSecret(secret))
            {
                ownSecrets.Add(secret);
            }
        }

        var ownResult = await inner.ValidateAsync(ownSecrets, parsedSecret, cancellationToken);
        var secretKind = ownResult.Success ? OwnSecretKind : InheritedSecretKind;

        var tenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(tenantId))
        {
            tenantId = UnresolvedTenantId;
        }

        logger.Log(
            ownResult.Success ? LogLevel.Information : LogLevel.Warning,
            MirrorSecretUsageEventId,
            "MirrorSecretUsage secretKind={MirrorSecretKind} clientId={ClientId} tenantId={TenantId} " +
            "— a mirrored client authenticated with this secret (AB#5065)",
            secretKind, parsedSecret.Id, tenantId);
    }

    /// <summary>
    ///     True when the list carries the mirror-own marker, i.e. when there is anything to tell
    ///     apart at all. Indexes rather than enumerates where possible so the ordinary client — the
    ///     overwhelming majority of every token request — does not even allocate an enumerator.
    /// </summary>
    private static bool ContainsOwnSecret(IEnumerable<Secret> secrets)
    {
        if (secrets is IList<Secret> list)
        {
            for (var i = 0; i < list.Count; i++)
            {
                if (IsOwnSecret(list[i]))
                {
                    return true;
                }
            }

            return false;
        }

        foreach (var secret in secrets)
        {
            if (IsOwnSecret(secret))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    ///     The marker AB#5061 puts on a mirror's own secret. Compared here against Duende's
    ///     <see cref="Secret" /> rather than in <see cref="ClientMirrorSecrets" />, which stays free
    ///     of protocol types for the OpenIddict migration (Epic 4989); the AutoMapper
    ///     <c>RtSecretRecord → Secret</c> map carries the description across unchanged.
    /// </summary>
    private static bool IsOwnSecret(Secret secret) =>
        string.Equals(secret.Description, ClientMirrorSecrets.OwnSecretDescription, StringComparison.Ordinal);
}

/// <summary>
///     Wires <see cref="MirrorSecretUsageTelemetryValidator" /> in front of Duende's own
///     <see cref="ISecretsListValidator" /> (AB#5065).
/// </summary>
/// <remarks>
///     An extension method rather than four lines in <c>Program.cs</c> so the wiring itself is
///     testable: that the decorator actually wins over Duende's registration, and that the inner
///     <see cref="SecretValidator" /> is constructible from the container, are exactly the two things
///     that would otherwise only fail at the token endpoint of a running service. Pinned by
///     <c>MirrorSecretUsageTelemetryTests.Registration_DecoratesDuendesOwnSecretsListValidator</c>.
/// </remarks>
public static class MirrorSecretUsageTelemetryRegistration
{
    /// <summary>
    ///     Must be called <b>after</b> <c>AddIdentityServer()</c> — the last registration of
    ///     <see cref="ISecretsListValidator" /> is the one Duende's <c>ClientSecretValidator</c> and
    ///     <c>ApiSecretValidator</c> resolve.
    /// </summary>
    public static IServiceCollection AddMirrorSecretUsageTelemetry(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        return services.AddTransient<ISecretsListValidator>(sp =>
            new MirrorSecretUsageTelemetryValidator(
                // The inner validator is built here rather than resolved, so decorating cannot
                // resolve to itself. TimeProvider is passed explicitly rather than left to the
                // container: SecretValidator needs it for secret expiry, and a missing registration
                // would surface only as a failing token endpoint.
                ActivatorUtilities.CreateInstance<SecretValidator>(sp,
                    sp.GetService<TimeProvider>() ?? TimeProvider.System),
                sp.GetRequiredService<IHttpContextAccessor>(),
                sp.GetRequiredService<ILogger<MirrorSecretUsageTelemetryValidator>>()));
    }
}
