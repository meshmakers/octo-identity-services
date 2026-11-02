using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Declared error codes of the client secret methods (System.Identity 2.29.0, AB#7773).</summary>
internal static class ClientSecretMethodErrors
{
    /// <summary><c>Client.AddSecret</c>: the client is public (<c>RequireClientSecret</c> is false) and never uses a secret.</summary>
    public const string ClientSecretNotRequired = "CLIENT_SECRET_NOT_REQUIRED";

    /// <summary><c>Client.RemoveSecret</c>: the client has no secret with the given value.</summary>
    public const string SecretNotFound = "SECRET_NOT_FOUND";
}

/// <summary>
///     Shared flow of <c>Client.AddSecret</c> and <c>Client.RemoveSecret</c> (AB#7780): caller rule, target, tenant binding,
///     version-checked write of the client (mirror sync and cache event as <c>ApiSecretsController</c>) and
///     exactly one <c>Identity.Method</c> event per call.
/// </summary>
/// <remarks>
///     <para>
///         <b>Caller.</b> REST parity (AB#5861): <c>IdentitySecretAdministrationPolicy</c> = scope <c>octo_api</c> and tenant
///         role <c>SecretManagement</c>, staged by <c>SecretManagementRoleEnforcement</c> (in <c>Warn</c>, the default,
///         <c>TenantManagement</c> or <c>UserManagement</c> still pass and are logged). The gateway checks the declared roles
///         (still <c>TenantManagement</c>, <c>UserManagement</c> in the CK model — changing them is a CK model change and
///         follows with the next System.Identity bump); the handler checks scope and role again on the principal the host
///         validated from the forwarded token, before the target is looked up, so a forged bus message or an unauthorized
///         caller gets <c>METHOD_FORBIDDEN</c> whether the target exists or not.
///     </para>
///     <para>
///         <b>Secrets.</b> The generated secret (result of <c>AddSecret</c>) and <c>secretValue</c> (parameter of
///         <c>RemoveSecret</c>) never reach a log line, an audit detail or an error parameter. Only the hash is stored, in the
///         legacy format <see cref="OpenIddict.OctoSecretHasher" /> validates (Base64 SHA-256), so the token endpoint accepts it
///         unchanged. The audit names tenant, method, target, caller and outcome plus <c>clientId</c> and a count; never a
///         secret, a hash or the free-text description.
///     </para>
/// </remarks>
internal abstract class ClientSecretMethodHandlerBase(IServiceProvider services)
{
    /// <summary>Audit detail: OAuth client id of the target.</summary>
    internal const string ClientIdDetail = "clientId";

    /// <summary>Audit detail: number of secret records of the client after the call.</summary>
    internal const string SecretCountDetail = "secretCount";

    protected IServiceProvider Services { get; } = services;

    /// <summary>
    ///     Decides whether the validated principal may administer client secrets: scope <c>octo_api</c> and the shared
    ///     requirement of the REST policy (<c>IdentityApiAuthorizationPolicies.SecretAdministrationRequirement</c>, AB#5861).
    ///     A principal without the scope is always <see cref="IdentityApiRoleDecision.Denied" />.
    /// </summary>
    internal static IdentityApiRoleDecision DecideClientSecretCaller(CkMethodPrincipal? principal,
        IdentityApiAuthorizationOptions options)
    {
        if (principal == null || !principal.Scopes.Contains(CommonConstants.OctoApiFullAccess, StringComparer.Ordinal))
        {
            return IdentityApiRoleDecision.Denied;
        }

        return IdentityApiAuthorizationPolicies.SecretAdministrationRequirement.Decide(
            role => principal.Roles.Contains(role, StringComparer.OrdinalIgnoreCase), options);
    }

    private bool IsClientAdministrator(CkMethodPrincipal? principal, string tenantId)
    {
        var decision = DecideClientSecretCaller(principal,
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
    ///     Checks the caller, binds the tenant and loads the target client. Returns the failure to answer, or the client.
    /// </summary>
    protected async Task<(CkMethodFailure? Failure, RtClient? Client)> ResolveTargetAsync(
        CkMethodPrincipal? principal, string tenantId, string? targetRtId, Dictionary<string, string> details)
    {
        if (!IsClientAdministrator(principal, tenantId))
        {
            return (CkMethodOutcome.Forbidden("role-required").Failure, null);
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
        RtClient? client;
        using (var session = await repository.GetSessionAsync().ConfigureAwait(false))
        {
            session.StartTransaction();
            client = await repository.GetRtEntityByRtIdAsync<RtClient>(session, rtId).ConfigureAwait(false);
            await session.CommitTransactionAsync().ConfigureAwait(false);
        }

        if (client == null || string.IsNullOrWhiteSpace(client.ClientId))
        {
            return (CkMethodOutcome.TargetNotFound().Failure, null);
        }

        details[ClientIdDetail] = client.ClientId;
        return (null, client);
    }

    /// <summary>Attempts of the version-checked read-modify-write before the call fails (<c>METHOD_HANDLER_FAILED</c>).</summary>
    internal const int MaxConcurrencyAttempts = 20;

    /// <summary>
    ///     Applies <paramref name="mutate" /> to the stored client as one version-checked read-modify-write: read in a
    ///     transaction, change, replace with the version that was read (the engine refuses the replace when another writer was
    ///     in between), re-read and re-apply on a conflict. So a concurrent <c>AddSecret</c> can never bring back a secret that
    ///     <c>RemoveSecret</c> removed, and two concurrent adds both keep their secret. <paramref name="mutate" /> returns a
    ///     failure to answer without writing, or <c>null</c> to write. After the commit the mirrors of a flagged client are synced
    ///     and the client cache update is published, both best effort (as <c>ClientStore.UpdateAsync</c> and REST do).
    /// </summary>
    protected async Task<CkMethodFailure?> MutateClientAsync(OctoObjectId clientRtId,
        Func<RtClient, CkMethodFailure?> mutate, Dictionary<string, string> details, CancellationToken cancellationToken)
    {
        var tenantResolver = Services.GetRequiredService<IMultiTenancyResolverService>();
        var repository = tenantResolver.GetTenantRepository();
        RtClient? saved = null;
        for (var attempt = 1;; attempt++)
        {
            try
            {
                var (failure, client) = await MongoWriteRetry.ExecuteTransactionWithRetryAsync(async () =>
                {
                    using var session = await repository.GetSessionAsync().ConfigureAwait(false);
                    session.StartTransaction();
                    try
                    {
                        var current = await repository.GetRtEntityByRtIdAsync<RtClient>(session, clientRtId)
                            .ConfigureAwait(false);
                        if (current == null)
                        {
                            await session.AbortTransactionAsync().ConfigureAwait(false);
                            return (CkMethodOutcome.TargetNotFound().Failure, (RtClient?)null);
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

                saved = client;
                break;
            }
            catch (RtVersionConflictException) when (attempt < MaxConcurrencyAttempts)
            {
                // Another writer was faster: nothing was written, read again and re-apply.
            }

            await Task.Delay(Random.Shared.Next(1, 4 * attempt + 1), cancellationToken).ConfigureAwait(false);
        }

        details[SecretCountDetail] =
            (saved!.ClientSecrets?.Count ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture);
        await AfterCommitAsync(repository.TenantId, saved).ConfigureAwait(false);
        return null;
    }

    /// <summary>
    ///     Mirror sync and the <c>CorsClientsUpdate</c> event after the write committed. Best effort and bounded: a failure or a
    ///     broker that does not answer never turns a committed change into a failed call (AddSecret would otherwise store a
    ///     secret it never hands out). Logs the tenant and the client id only.
    /// </summary>
    private async Task AfterCommitAsync(string tenantId, RtClient client)
    {
        var logger = Services.GetRequiredService<ILogger<ClientSecretMethodHandlerBase>>();
        if (client.AutoProvisionInChildTenants)
        {
            try
            {
                await Services.GetRequiredService<IClientMirrorProvisioningService>()
                    .SyncMirrorsForClientAsync(tenantId, client).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Mirror sync failed after a secret change of client '{ClientId}' in tenant '{TenantId}'",
                    client.ClientId, tenantId);
            }
        }

        try
        {
            var publish = Services.GetRequiredService<IDistributionEventHubService>()
                .PublishAsync(new CorsClientsUpdate(tenantId, Guid.NewGuid(), DateTime.Now));
            _ = publish.ContinueWith(static t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            await publish.WaitAsync(PublishTimeout).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to publish CorsClientsUpdate for tenant '{TenantId}'; the CORS policy cache heals on its TTL", tenantId);
        }
    }

    /// <summary>How long the handler waits for the <c>CorsClientsUpdate</c> publish.</summary>
    internal static readonly TimeSpan PublishTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Writes the one <c>Identity.Method</c> event of the call (also for refusals and exceptions).</summary>
    protected Task AuditAsync<TParameters>(CkMethodContext<TParameters> context, string outcome,
        IReadOnlyDictionary<string, string> details) where TParameters : class =>
        Services.GetRequiredService<IIdentityMethodAuditWriter>().RecordAsync(context.TenantId, context.MethodId,
            context.InvocationId, context.TargetRtId, context.CallerPrincipal?.Subject, outcome,
            details.Count > 0 ? details : null);
}
