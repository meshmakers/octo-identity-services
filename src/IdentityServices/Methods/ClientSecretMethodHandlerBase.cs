using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Declared error codes of the secret methods (System.Identity 2.29.0 and 3.4.0).</summary>
internal static class ClientSecretMethodErrors
{
    /// <summary><c>Client.AddSecret</c>: the client is public (<c>RequireClientSecret</c> is false) and never uses a secret.</summary>
    public const string ClientSecretNotRequired = "CLIENT_SECRET_NOT_REQUIRED";

    /// <summary><c>*.RemoveSecret</c>, <c>*.UpdateSecret</c>: the owner has no secret with the given value.</summary>
    public const string SecretNotFound = "SECRET_NOT_FOUND";

    /// <summary>
    ///     <c>Client.UpdateSecret</c> and the <c>ApiResource</c> secret methods (3.4.0): the version-checked write lost against
    ///     concurrent writers <see cref="SecretOwnerMethodHandlerBase{TOwner}.MaxConcurrencyAttempts" /> times. Not declared on
    ///     <c>Client.AddSecret-1</c> / <c>Client.RemoveSecret-1</c> (a new error code there would be a Major, row M8): they
    ///     answer <c>METHOD_HANDLER_FAILED</c> in that case.
    /// </summary>
    public const string ConcurrentChange = "CONCURRENT_CHANGE";
}

/// <summary>
///     Shared flow of the secret methods of a secret owner (<c>Client.*Secret</c>, <c>ApiResource.*Secret</c>):
///     caller rule, tenant binding, target and its data permission, version-checked write of the owner (cache event
///     as <c>ApiSecretsController</c>) and exactly one <c>Identity.Method</c> event per call.
/// </summary>
/// <remarks>
///     <para>
///         <b>Caller.</b> REST parity (AB#5861): <c>IdentitySecretAdministrationPolicy</c> = scope <c>octo_api</c> and tenant
///         role <c>SecretManagement</c>, staged by <c>SecretManagementRoleEnforcement</c> (in <c>Warn</c>, the default,
///         <c>TenantManagement</c> or <c>UserManagement</c> still pass and are logged). The gateway checks the declared roles
///         (System.Identity 3.1.0, AB#8095: <c>TenantManagement</c>, <c>UserManagement</c>, <c>SecretManagement</c>; the first
///         two leave the declaration with the next major); the handler checks scope and role again on the principal the host
///         validated from the forwarded token, before the target is looked up, so a forged bus message or an unauthorized
///         caller gets <c>METHOD_FORBIDDEN</c> whether the target exists or not.
///     </para>
///     <para>
///         <b>Target data permission.</b> The secrets are part of the owner. Before anything is changed the owner is
///         evaluated for <c>Write</c> with the caller's roles (<see cref="IRtDataPermissionEvaluator" />): an owner the caller
///         cannot read answers like a missing one (<c>METHOD_TARGET_NOT_FOUND</c>), one they may read but not write is
///         <c>METHOD_FORBIDDEN</c> (<c>reason</c> = <c>data-permission</c>). The GraphQL gateway checks the declared
///         <c>dataAccess: Write</c> on the target already; the REST facades call in-process, where only the handler can check
///         it. Without an enforcing data policy on the owner type (the default) both are open.
///     </para>
///     <para>
///         <b>Secrets.</b> The generated secret (result of <c>AddSecret</c>) and <c>secretValue</c> (parameter of
///         <c>RemoveSecret</c> / <c>UpdateSecret</c>) never reach a log line, an audit detail or an error parameter. Only the
///         hash is stored, in the legacy format <see cref="OpenIddict.OctoSecretHasher" /> validates (Base64 SHA-256). The audit
///         names tenant, method, target, caller and outcome plus the owner name and a count; never a secret, a hash or the
///         free-text description.
///     </para>
/// </remarks>
/// <typeparam name="TOwner">The entity that holds the secrets (<see cref="RtClient" />, <see cref="RtApiResource" />).</typeparam>
internal abstract class SecretOwnerMethodHandlerBase<TOwner>(IServiceProvider services) where TOwner : RtEntity, new()
{
    /// <summary>Audit detail: number of secret records of the owner after the call.</summary>
    internal const string SecretCountDetail = "secretCount";

    /// <summary>Parameter of a caller refusal: the tenant role to ask for.</summary>
    internal const string RequiredRoleParameter = "requiredRole";

    /// <summary>Attempts of the version-checked read-modify-write before the call fails.</summary>
    internal const int MaxConcurrencyAttempts = 20;

    /// <summary>How long the handler waits for the <c>CorsClientsUpdate</c> publish.</summary>
    internal static readonly TimeSpan PublishTimeout = TimeSpan.FromSeconds(5);

    protected IServiceProvider Services { get; } = services;

    /// <summary>The audit detail key of the owner name (<c>clientId</c>, <c>apiResourceName</c>).</summary>
    protected abstract string OwnerDetailKey { get; }

    /// <summary>The name of the owner REST addresses it by (OAuth client id, API resource name); blank = not usable.</summary>
    protected abstract string? OwnerName(TOwner owner);

    /// <summary>The stored secret list of the owner, <c>null</c> when it has none.</summary>
    protected abstract IAttributeValueList<RtSecretRecord>? Secrets(TOwner owner);

    /// <summary>The stored secret list of the owner, created when it has none.</summary>
    protected abstract IAttributeValueList<RtSecretRecord> EnsureSecrets(TOwner owner);

    /// <summary>
    ///     Decides whether the validated principal may administer secrets: scope <c>octo_api</c> and the shared requirement of
    ///     the REST policy (<c>IdentityApiAuthorizationPolicies.SecretAdministrationRequirement</c>). A principal without
    ///     the scope is always <see cref="IdentityApiRoleDecision.Denied" />.
    /// </summary>
    internal static IdentityApiRoleDecision DecideSecretCaller(CkMethodPrincipal? principal,
        IdentityApiAuthorizationOptions options)
    {
        if (principal == null || !principal.Scopes.Contains(CommonConstants.OctoApiFullAccess, StringComparer.Ordinal))
        {
            return IdentityApiRoleDecision.Denied;
        }

        return IdentityApiAuthorizationPolicies.SecretAdministrationRequirement.Decide(
            role => principal.Roles.Contains(role, StringComparer.OrdinalIgnoreCase), options);
    }

    private bool IsSecretAdministrator(CkMethodPrincipal? principal, string tenantId)
    {
        var decision = DecideSecretCaller(principal,
            Services.GetRequiredService<IOptionsMonitor<IdentityApiAuthorizationOptions>>().CurrentValue);
        if (decision == IdentityApiRoleDecision.AllowedByStagedWarn)
        {
            // The same inventory line as the REST handler, so the rollout precheck finds method callers too.
            Services.GetRequiredService<ILogger<ClientSecretMethodHandlerBase>>().LogWarning(
                "Identity client secret method without required role allowed by SecretManagementRoleEnforcement=Warn in tenant {TenantId} by subject {Subject} / client {ClientId}, required any of [{RequiredRoles}]. " +
                "This would be denied with SecretManagementRoleEnforcement=Enforce (AB#5861)",
                tenantId, principal?.SubjectId, principal?.ClientId, CommonConstants.SecretManagementRole);
        }

        return decision != IdentityApiRoleDecision.Denied;
    }

    /// <summary>
    ///     <c>METHOD_FORBIDDEN</c> for a refused caller (<c>reason</c> = <c>role-required</c>). It names the role the caller
    ///     must ask for, <c>SecretManagement</c> (AB#8095, like the REST 403 message of AB#5861), and nothing about the target,
    ///     so an existing and a missing target are refused identically.
    /// </summary>
    internal static CkMethodFailure CallerForbidden()
    {
        var forbidden = CkMethodOutcome.Forbidden("role-required").Failure!;
        var parameters = new Dictionary<string, string>(forbidden.Parameters, StringComparer.Ordinal)
        {
            [RequiredRoleParameter] = CommonConstants.SecretManagementRole
        };
        return new CkMethodFailure(forbidden.Code, parameters, forbidden.Details);
    }

    /// <summary>
    ///     Checks the caller, binds the tenant, loads the owner and checks that the caller may write it (data permission).
    ///     Returns the failure to answer, or the owner.
    /// </summary>
    protected async Task<(CkMethodFailure? Failure, TOwner? Owner)> ResolveTargetAsync(
        CkMethodPrincipal? principal, string tenantId, string? targetRtId, Dictionary<string, string> details,
        CancellationToken cancellationToken = default)
    {
        if (!IsSecretAdministrator(principal, tenantId))
        {
            return (CallerForbidden(), null);
        }

        // A target that is not an object id cannot exist (the repository would throw on it).
        if (string.IsNullOrWhiteSpace(targetRtId) || !OctoObjectId.TryParse(targetRtId, out var rtId))
        {
            return (CkMethodOutcome.TargetNotFound().Failure, null);
        }

        if (!await Services.GetRequiredService<IMethodTenantAccessor>().BindAsync(tenantId).ConfigureAwait(false))
        {
            return (CkMethodOutcome.TargetNotFound().Failure, null);
        }

        var repository = Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        TOwner? owner;
        using (var session = await repository.GetSessionAsync().ConfigureAwait(false))
        {
            session.StartTransaction();
            owner = await repository.GetRtEntityByRtIdAsync<TOwner>(session, rtId).ConfigureAwait(false);
            await session.CommitTransactionAsync().ConfigureAwait(false);
        }

        if (owner == null || string.IsNullOrWhiteSpace(OwnerName(owner)))
        {
            return (CkMethodOutcome.TargetNotFound().Failure, null);
        }

        // The secrets are part of the owner: a caller who cannot read it gets no answer that tells it exists, one who may
        // read but not write it changes nothing (the in-process REST path has no gateway check of dataAccess).
        var verdict = await Services.GetRequiredService<IRtDataPermissionEvaluator>()
            .EvaluateAsync(repository, IdentityMethodCallerRules.ToSecurityContext(principal!),
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<TOwner>(), owner.RtId), RtDataAction.Write,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (verdict.Decision == RtDataPermissionDecision.NotVisible)
        {
            return (CkMethodOutcome.TargetNotFound().Failure, null);
        }

        details[OwnerDetailKey] = OwnerName(owner)!;
        if (!verdict.IsAllowed)
        {
            details["reason"] = "data-permission";
            return (new CkMethodFailure(CkMethodErrorCodes.MethodForbidden,
                new Dictionary<string, string> { ["reason"] = "data-permission" }), null);
        }

        return (null, owner);
    }

    /// <summary>
    ///     Applies <paramref name="mutate" /> to the stored owner as one version-checked read-modify-write: read in a
    ///     transaction, change, replace with the version that was read (the engine refuses the replace when another writer was
    ///     in between), re-read and re-apply on a conflict. So a concurrent add can never bring back a secret that a remove
    ///     removed, and two concurrent adds both keep their secret. <paramref name="mutate" /> returns a failure to answer
    ///     without writing, or <c>null</c> to write. After <see cref="MaxConcurrencyAttempts" /> lost writes the call answers
    ///     <paramref name="concurrentChangeCode" /> when the method declares one, else the conflict is thrown
    ///     (<c>METHOD_HANDLER_FAILED</c>). After the commit <see cref="AfterCommitAsync" /> runs (best effort).
    /// </summary>
    protected async Task<CkMethodFailure?> MutateOwnerAsync(OctoObjectId ownerRtId,
        Func<TOwner, CkMethodFailure?> mutate, Dictionary<string, string> details, string? concurrentChangeCode,
        CancellationToken cancellationToken)
    {
        var tenantResolver = Services.GetRequiredService<IMultiTenancyResolverService>();
        var repository = tenantResolver.GetTenantRepository();
        TOwner? saved = null;
        for (var attempt = 1;; attempt++)
        {
            try
            {
                var (failure, owner) = await MongoWriteRetry.ExecuteTransactionWithRetryAsync(async () =>
                {
                    using var session = await repository.GetSessionAsync().ConfigureAwait(false);
                    session.StartTransaction();
                    try
                    {
                        var current = await repository.GetRtEntityByRtIdAsync<TOwner>(session, ownerRtId)
                            .ConfigureAwait(false);
                        if (current == null)
                        {
                            await session.AbortTransactionAsync().ConfigureAwait(false);
                            return (CkMethodOutcome.TargetNotFound().Failure, (TOwner?)null);
                        }

                        var readVersion = current.RtVersion;
                        var refused = mutate(current);
                        if (refused != null)
                        {
                            await session.AbortTransactionAsync().ConfigureAwait(false);
                            return (refused, null);
                        }

                        await repository.ReplaceOneRtEntityByIdAsync(session, current.RtId, current, readVersion)
                            .ConfigureAwait(false);
                        await session.CommitTransactionAsync().ConfigureAwait(false);
                        return ((CkMethodFailure?)null, current);
                    }
                    catch
                    {
                        try
                        {
                            await session.AbortTransactionAsync().ConfigureAwait(false);
                        }
                        catch (Exception)
                        {
                            // The transaction is gone already; the original exception is what matters.
                        }

                        throw;
                    }
                }, MaxConcurrencyAttempts, cancellationToken).ConfigureAwait(false);

                if (failure != null)
                {
                    return failure;
                }

                saved = owner;
                break;
            }
            catch (RtVersionConflictException) when (attempt < MaxConcurrencyAttempts)
            {
                // Another writer was faster: nothing was written, read again and re-apply.
            }
            catch (RtVersionConflictException) when (concurrentChangeCode != null)
            {
                return new CkMethodFailure(concurrentChangeCode);
            }

            await Task.Delay(Random.Shared.Next(1, 4 * attempt + 1), cancellationToken).ConfigureAwait(false);
        }

        details[SecretCountDetail] =
            (Secrets(saved!)?.Count ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture);
        await AfterCommitAsync(repository.TenantId, saved!).ConfigureAwait(false);
        return null;
    }

    /// <summary>
    ///     Runs after the write committed: the <c>CorsClientsUpdate</c> event (the identity resource cache, as
    ///     <c>ApiSecretsController</c> publishes it). Best effort and bounded: a failure or a broker that does not answer never
    ///     turns a committed change into a failed call (AddSecret would otherwise store a secret it never hands out). Logs the
    ///     tenant only.
    /// </summary>
    protected virtual async Task AfterCommitAsync(string tenantId, TOwner owner)
    {
        try
        {
            var publish = Services.GetRequiredService<IDistributionEventHubService>()
                .PublishAsync(new CorsClientsUpdate(tenantId, Guid.NewGuid(), DateTime.Now));
            _ = publish.ContinueWith(static t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            await publish.WaitAsync(PublishTimeout).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Services.GetRequiredService<ILogger<ClientSecretMethodHandlerBase>>().LogWarning(ex,
                "Failed to publish CorsClientsUpdate for tenant '{TenantId}'; the CORS policy cache heals on its TTL", tenantId);
        }
    }

    /// <summary>Audit detail: number of secret records the call removed.</summary>
    internal const string RemovedCountDetail = "removedCount";

    /// <summary>
    ///     Generates a new secret and stores its hash on the owner. <paramref name="refuse" /> may refuse the owner inside the
    ///     write (e.g. a public client). Returns the failure, or the clear text (shown once, never logged).
    /// </summary>
    protected async Task<(CkMethodFailure? Failure, string? ClearText)> AddSecretCoreAsync(CkMethodPrincipal? principal,
        string tenantId, string? targetRtId, string? description, DateTime? expirationDate,
        Func<TOwner, CkMethodFailure?>? refuse, string? concurrentChangeCode, Dictionary<string, string> details,
        CancellationToken cancellationToken)
    {
        var (failure, owner) = await ResolveTargetAsync(principal, tenantId, targetRtId, details, cancellationToken)
            .ConfigureAwait(false);
        if (failure != null)
        {
            return (failure, null);
        }

        var expiration = expirationDate?.ToUniversalTime();
        if (expiration != null && expiration <= DateTime.UtcNow)
        {
            return (CkMethodOutcome.ValidationFailed("expirationDate", "in-the-past").Failure, null);
        }

        // The mirror machinery treats this description as the marker of a mirror's own secret; a user-supplied
        // secret with it would be carried into the child tenants as if it were their own credential.
        if (string.Equals(description, ClientMirrorSecrets.OwnSecretDescription, StringComparison.Ordinal))
        {
            return (CkMethodOutcome.ValidationFailed("description", "reserved").Failure, null);
        }

        // Generated once, outside the write: a retried write stores the same hash as the clear text returned.
        var clearText = ClientMirrorSecrets.GenerateSecret();
        var hash = OpenIddict.OctoSecretHasher.HashSecret(clearText);
        var refused = await MutateOwnerAsync(owner!.RtId, current =>
        {
            if (refuse?.Invoke(current) is { } refusal)
            {
                return refusal;
            }

            EnsureSecrets(current).Add(new RtSecretRecord
            {
                Type = ClientMirrorSecrets.SharedSecretType,
                Value = hash,
                Description = description,
                ExpirationDateTime = expiration
            });
            return null;
        }, details, concurrentChangeCode, cancellationToken).ConfigureAwait(false);
        return refused != null ? (refused, null) : (null, clearText);
    }

    /// <summary>Removes every secret of the owner that matches <paramref name="secretValue" /> (<see cref="Matches" />).</summary>
    protected async Task<CkMethodFailure?> RemoveSecretCoreAsync(CkMethodPrincipal? principal, string tenantId,
        string? targetRtId, string? secretValue, string? concurrentChangeCode, Dictionary<string, string> details,
        CancellationToken cancellationToken)
    {
        var (failure, owner) = await ResolveTargetAsync(principal, tenantId, targetRtId, details, cancellationToken)
            .ConfigureAwait(false);
        if (failure != null)
        {
            return failure;
        }

        if (string.IsNullOrEmpty(secretValue))
        {
            return CkMethodOutcome.ValidationFailed("secretValue", "required").Failure;
        }

        var removed = 0;
        var refused = await MutateOwnerAsync(owner!.RtId, current =>
        {
            // RemoveAll with a predicate: the list hands out wrapper instances of the stored records, so a Remove by
            // instance does not find a record that was read from the database.
            removed = Secrets(current)?.RemoveAll(s => Matches(s, secretValue)) ?? 0;
            return removed == 0 ? new CkMethodFailure(ClientSecretMethodErrors.SecretNotFound) : null;
        }, details, concurrentChangeCode, cancellationToken).ConfigureAwait(false);
        details[RemovedCountDetail] = removed.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return refused;
    }

    /// <summary>
    ///     Replaces description and expiration date of the first secret that matches <paramref name="secretValue" />; value
    ///     and type stay. An omitted description or expiration date is cleared (REST <c>PUT</c> parity).
    /// </summary>
    protected async Task<CkMethodFailure?> UpdateSecretCoreAsync(CkMethodPrincipal? principal, string tenantId,
        string? targetRtId, string? secretValue, string? description, DateTime? expirationDate,
        Dictionary<string, string> details, CancellationToken cancellationToken)
    {
        var (failure, owner) = await ResolveTargetAsync(principal, tenantId, targetRtId, details, cancellationToken)
            .ConfigureAwait(false);
        if (failure != null)
        {
            return failure;
        }

        if (string.IsNullOrEmpty(secretValue))
        {
            return CkMethodOutcome.ValidationFailed("secretValue", "required").Failure;
        }

        // The mirror machinery's marker is reserved here as on AddSecret: an update must not turn a user secret
        // into what the mirror sync treats as a mirror's own credential, nor (below) a mirror's own secret into a user secret.
        if (string.Equals(description, ClientMirrorSecrets.OwnSecretDescription, StringComparison.Ordinal))
        {
            return CkMethodOutcome.ValidationFailed("description", "reserved").Failure;
        }

        var expiration = expirationDate?.ToUniversalTime();
        return await MutateOwnerAsync(owner!.RtId, current =>
        {
            var secrets = Secrets(current);
            for (var i = 0; i < (secrets?.Count ?? 0); i++)
            {
                if (!Matches(secrets![i], secretValue))
                {
                    continue;
                }

                // A mirror's own secret carries the marker the mirror sync relies on; overwriting its
                // description would turn it into what the sync treats as an inherited copy.
                if (ClientMirrorSecrets.IsOwnSecret(secrets[i]))
                {
                    return CkMethodOutcome.ValidationFailed("description", "reserved").Failure;
                }

                // The records handed out by the list are snapshots: the updated record replaces the old one.
                secrets[i] = new RtSecretRecord
                {
                    Type = secrets[i].Type,
                    Value = secrets[i].Value,
                    Description = description,
                    ExpirationDateTime = expiration
                };
                return null;
            }

            return new CkMethodFailure(ClientSecretMethodErrors.SecretNotFound);
        }, details, ClientSecretMethodErrors.ConcurrentChange, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    ///     The stored value as listed, or the clear text hashed as the token endpoint does (fixed-time compare). The empty
    ///     value never matches.
    /// </summary>
    internal static bool Matches(RtSecretRecord secret, string secretValue) =>
        !string.IsNullOrEmpty(secret.Value) && !string.IsNullOrEmpty(secretValue) &&
        (string.Equals(secret.Value, secretValue, StringComparison.Ordinal) ||
         OpenIddict.OctoSecretHasher.Matches(secretValue, secret.Value));

    /// <summary>Writes the one <c>Identity.Method</c> event of the call (also for refusals and exceptions).</summary>
    protected Task AuditAsync<TParameters>(CkMethodContext<TParameters> context, string outcome,
        IReadOnlyDictionary<string, string> details) where TParameters : class =>
        Services.GetRequiredService<IIdentityMethodAuditWriter>().RecordAsync(context.TenantId, context.MethodId,
            context.InvocationId, context.TargetRtId, context.CallerPrincipal?.Subject, outcome,
            details.Count > 0 ? details : null);

    /// <summary>
    ///     Runs <paramref name="body" /> and writes exactly one audit record for it, also when it throws (the host answers
    ///     <c>METHOD_HANDLER_FAILED</c> then).
    /// </summary>
    protected async Task<TOutcome> AuditedAsync<TParameters, TOutcome>(CkMethodContext<TParameters> context,
        Func<Dictionary<string, string>, Task<TOutcome>> body, Func<TOutcome, string?> failureCode)
        where TParameters : class
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        var outcomeCode = "METHOD_HANDLER_FAILED";
        try
        {
            var outcome = await body(details).ConfigureAwait(false);
            outcomeCode = failureCode(outcome) ?? IdentityMethodAuditWriter.SuccessOutcome;
            return outcome;
        }
        finally
        {
            await AuditAsync(context, outcomeCode, details).ConfigureAwait(false);
        }
    }
}

/// <summary>
///     Shared flow of the client secret methods <c>Client.AddSecret</c>, <c>Client.RemoveSecret</c> and
///     <c>Client.UpdateSecret</c>, see <see cref="SecretOwnerMethodHandlerBase{TOwner}" />. After the write the mirrors
///     of a flagged client are synced (as <c>ClientStore.UpdateAsync</c> and REST do), then the cache event is published.
/// </summary>
internal abstract class ClientSecretMethodHandlerBase(IServiceProvider services)
    : SecretOwnerMethodHandlerBase<RtClient>(services)
{
    /// <summary>Audit detail: OAuth client id of the target.</summary>
    internal const string ClientIdDetail = "clientId";

    protected override string OwnerDetailKey => ClientIdDetail;

    protected override string? OwnerName(RtClient owner) => owner.ClientId;

    protected override IAttributeValueList<RtSecretRecord>? Secrets(RtClient owner) => owner.ClientSecrets;

    protected override IAttributeValueList<RtSecretRecord> EnsureSecrets(RtClient owner) =>
        owner.ClientSecrets ??= new AttributeRecordValueList<RtSecretRecord>();

    /// <summary>See <see cref="SecretOwnerMethodHandlerBase{TOwner}.DecideSecretCaller" />.</summary>
    internal static IdentityApiRoleDecision DecideClientSecretCaller(CkMethodPrincipal? principal,
        IdentityApiAuthorizationOptions options) => DecideSecretCaller(principal, options);

    protected override async Task AfterCommitAsync(string tenantId, RtClient client)
    {
        if (client.AutoProvisionInChildTenants)
        {
            try
            {
                await Services.GetRequiredService<IClientMirrorProvisioningService>()
                    .SyncMirrorsForClientAsync(tenantId, client).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Services.GetRequiredService<ILogger<ClientSecretMethodHandlerBase>>().LogError(ex,
                    "Mirror sync failed after a secret change of client '{ClientId}' in tenant '{TenantId}'",
                    client.ClientId, tenantId);
            }
        }

        await base.AfterCommitAsync(tenantId, client).ConfigureAwait(false);
    }
}

/// <summary>
///     Shared flow of the API resource secret methods <c>ApiResource.AddSecret</c>, <c>RemoveSecret</c> and
///     <c>UpdateSecret</c> (System.Identity 3.4.0), see <see cref="SecretOwnerMethodHandlerBase{TOwner}" />.
/// </summary>
internal abstract class ApiResourceSecretMethodHandlerBase(IServiceProvider services)
    : SecretOwnerMethodHandlerBase<RtApiResource>(services)
{
    /// <summary>Audit detail: name of the target API resource.</summary>
    internal const string ApiResourceNameDetail = "apiResourceName";

    protected override string OwnerDetailKey => ApiResourceNameDetail;

    protected override string? OwnerName(RtApiResource owner) => owner.Name;

    protected override IAttributeValueList<RtSecretRecord>? Secrets(RtApiResource owner) => owner.ApiSecrets;

    protected override IAttributeValueList<RtSecretRecord> EnsureSecrets(RtApiResource owner) =>
        owner.ApiSecrets ??= new AttributeRecordValueList<RtSecretRecord>();
}
