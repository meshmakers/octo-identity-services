using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

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
///     write through <see cref="IOctoClientStore" /> (the store of <c>ApiSecretsController</c>, incl. the mirror sync) and
///     exactly one <c>Identity.Method</c> event per call.
/// </summary>
/// <remarks>
///     <para>
///         <b>Caller.</b> REST parity: <c>IdentityTenantAdministrationWritePolicy</c> = scope <c>octo_api</c> and tenant role
///         <c>TenantManagement</c> or <c>UserManagement</c>. The gateway checks the declared roles; the handler checks scope and
///         role again on the principal the host validated from the forwarded token, before the target is looked up, so a forged
///         bus message or an unauthorized caller gets <c>METHOD_FORBIDDEN</c> whether the target exists or not.
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
    ///     <c>true</c> when the validated principal may administer client secrets: scope <c>octo_api</c> and role
    ///     <c>TenantManagement</c> or <c>UserManagement</c> (<c>TenantAdministrationRoles</c> of the REST policies).
    /// </summary>
    internal static bool IsClientAdministrator(CkMethodPrincipal? principal) =>
        principal != null &&
        principal.Scopes.Contains(CommonConstants.OctoApiFullAccess, StringComparer.Ordinal) &&
        (principal.Roles.Contains(CommonConstants.TenantManagementRole, StringComparer.OrdinalIgnoreCase) ||
         principal.Roles.Contains(CommonConstants.UserManagementRole, StringComparer.OrdinalIgnoreCase));

    /// <summary>
    ///     Checks the caller, binds the tenant and loads the target client. Returns the failure to answer, or the client.
    /// </summary>
    protected async Task<(CkMethodFailure? Failure, RtClient? Client)> ResolveTargetAsync(
        CkMethodPrincipal? principal, string tenantId, string? targetRtId, Dictionary<string, string> details)
    {
        if (!IsClientAdministrator(principal))
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

    /// <summary>
    ///     Writes the changed secret list through the client store (replace of the client entity and mirror sync, as REST) and
    ///     publishes the client cache update REST publishes.
    /// </summary>
    protected async Task SaveAsync(RtClient client, Dictionary<string, string> details)
    {
        var clientStore = Services.GetRequiredService<IOctoClientStore>();
        await clientStore.UpdateAsync(client.ClientId, client).ConfigureAwait(false);
        details[SecretCountDetail] = (client.ClientSecrets?.Count ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture);
        await Services.GetRequiredService<IDistributionEventHubService>()
            .PublishAsync(new CorsClientsUpdate(clientStore.TenantId, Guid.NewGuid(), DateTime.Now))
            .ConfigureAwait(false);
    }

    /// <summary>Writes the one <c>Identity.Method</c> event of the call (also for refusals and exceptions).</summary>
    protected Task AuditAsync<TParameters>(CkMethodContext<TParameters> context, string outcome,
        IReadOnlyDictionary<string, string> details) where TParameters : class =>
        Services.GetRequiredService<IIdentityMethodAuditWriter>().RecordAsync(context.TenantId, context.MethodId,
            context.InvocationId, context.TargetRtId, context.CallerPrincipal?.Subject, outcome,
            details.Count > 0 ? details : null);
}
