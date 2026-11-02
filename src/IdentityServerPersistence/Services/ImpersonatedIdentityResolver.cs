using IdentityServerPersistence.SystemStores;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Default <see cref="IImpersonatedIdentityResolver" /> (AB#5114): authorizes an actor client
///     against the explicit <c>System.Identity/MayActAs</c> edge and resolves the TARGET client's
///     effective roles, all in the current request tenant.
/// </summary>
/// <remarks>
///     <para>
///         The role set is produced by <see cref="IClientRoleStore.GetEffectiveRoleNamesAsync" /> on
///         the <b>target</b> — the same call <c>TokenEndpointController.HandleClientCredentialsAsync</c>
///         makes when the target authenticates with its own secret, so an impersonated token and a
///         genuine <c>client_credentials</c> token of the target carry identical role claims by
///         construction. The actor's own roles are never read — nothing of the actor's authority
///         leaks into the issued token beyond the audit-only <c>act</c> claim.
///     </para>
///     <para>
///         Every check fails closed: unknown actor, unknown target, disabled target and missing edge
///         are each their own denial so the audit trail says precisely why, while the processor maps
///         them onto OAuth errors that do not over-share with the caller.
///     </para>
/// </remarks>
public sealed class ImpersonatedIdentityResolver(
    IOctoClientStore clientStore,
    IClientRoleStore clientRoleStore,
    IClientImpersonationStore clientImpersonationStore,
    ILogger<ImpersonatedIdentityResolver> logger) : IImpersonatedIdentityResolver
{
    /// <inheritdoc />
    public async Task<ImpersonatedIdentityResult> ResolveAsync(
        string actorClientId, string targetClientId, CancellationToken cancellationToken = default)
    {
        var (denial, targetClient) = await AuthorizeCoreAsync(actorClientId, targetClientId);
        if (denial != ImpersonationDenialReason.None || targetClient == null)
        {
            return ImpersonatedIdentityResult.Denied(denial);
        }

        var roleNames = new HashSet<string>(
            await clientRoleStore.GetEffectiveRoleNamesAsync(targetClient.RtId),
            StringComparer.OrdinalIgnoreCase);

        logger.LogInformation(
            "Impersonation resolved: client '{ActorClientId}' acting as '{TargetClientId}' with {RoleCount} effective role(s)",
            actorClientId, targetClientId, roleNames.Count);

        return ImpersonatedIdentityResult.Granted(roleNames);
    }

    /// <inheritdoc />
    public async Task<ImpersonationDenialReason> AuthorizeActorAsync(
        string actorClientId, string targetClientId, CancellationToken cancellationToken = default)
    {
        var (denial, _) = await AuthorizeCoreAsync(actorClientId, targetClientId);
        return denial;
    }

    private async Task<(ImpersonationDenialReason denial, RtClient? targetClient)> AuthorizeCoreAsync(
        string actorClientId, string targetClientId)
    {
        if (string.IsNullOrWhiteSpace(actorClientId))
        {
            return (ImpersonationDenialReason.ActorNotFound, null);
        }

        if (string.IsNullOrWhiteSpace(targetClientId))
        {
            return (ImpersonationDenialReason.TargetNotFound, null);
        }

        // The actor authenticated against OpenIddict already, but authentication does not prove it
        // is provisioned in THIS tenant — and only a tenant-local Client entity can hold the edge.
        var actorClient = await clientStore.FindRtClientByIdAsync(actorClientId);
        if (actorClient == null)
        {
            logger.LogWarning(
                "Impersonation denied: actor client '{ActorClientId}' does not exist in the request tenant",
                actorClientId);
            return (ImpersonationDenialReason.ActorNotFound, null);
        }

        var targetClient = await clientStore.FindRtClientByIdAsync(targetClientId);
        if (targetClient == null)
        {
            logger.LogWarning(
                "Impersonation denied: target client '{TargetClientId}' does not exist in the request tenant (actor '{ActorClientId}')",
                targetClientId, actorClientId);
            return (ImpersonationDenialReason.TargetNotFound, null);
        }

        // A disabled client cannot obtain a token with its own secret — impersonation must not be a
        // side door around the disable switch.
        if (!targetClient.Enabled)
        {
            logger.LogWarning(
                "Impersonation denied: target client '{TargetClientId}' is disabled (actor '{ActorClientId}')",
                targetClientId, actorClientId);
            return (ImpersonationDenialReason.TargetDisabled, null);
        }

        // THE authorization: the explicit MayActAs edge, direction actor→target. Deliberately not
        // transitive and not group-aware — the edge is the entire, auditable policy surface.
        if (!await clientImpersonationStore.HasMayActAsEdgeAsync(actorClient.RtId, targetClient.RtId))
        {
            logger.LogWarning(
                "Impersonation denied: no MayActAs edge from '{ActorClientId}' to '{TargetClientId}' in the request tenant",
                actorClientId, targetClientId);
            return (ImpersonationDenialReason.NotAuthorized, null);
        }

        return (ImpersonationDenialReason.None, targetClient);
    }
}
