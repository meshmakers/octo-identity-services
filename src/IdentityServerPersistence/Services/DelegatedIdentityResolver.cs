using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Default <see cref="IDelegatedIdentityResolver" />: intersects the service account's effective
///     roles with the user's effective roles, both resolved in the current request tenant (AB#5026).
/// </summary>
/// <remarks>
///     <para>
///         <b>Both sides use the platform's existing effective-role machinery</b>, so direct
///         <c>AssignedRole</c> assignments and group-inherited roles (incl. nested groups) count
///         identically for a client and for a user:
///         <see cref="IClientRoleStore.GetEffectiveRoleNamesAsync" /> for the service account (the
///         same call <c>TokenEndpointController.HandleClientCredentialsAsync</c> makes when minting a plain
///         <c>client_credentials</c> token) and <see cref="IUserRoleStore{TUser}.GetRolesAsync" /> —
///         implemented by <c>OctoUserStore</c>, the store that produces a login token's <c>role</c>
///         claims.
///     </para>
///     <para>
///         <b>Case semantics.</b> Both sides return <c>RtRole.Name</c> values read from the same
///         <c>RtRole</c> entities in the same tenant, so their spelling is identical by
///         construction. The intersection nevertheless compares with
///         <see cref="StringComparer.OrdinalIgnoreCase" />, matching how role names are looked up
///         everywhere else in this repository (<c>ClientRoleStore.FindRoleByNameAsync</c> and
///         <c>OctoUserStore</c> both key off the upper-invariant <c>NormalizedName</c>). A
///         case-sensitive intersection would be a silent fail-open-to-empty if a role were ever
///         renamed in casing only. The <b>user-side</b> spelling is emitted, because that is the
///         spelling a non-delegated token for the same user would carry.
///     </para>
/// </remarks>
public sealed class DelegatedIdentityResolver(
    IOctoClientStore clientStore,
    IClientRoleStore clientRoleStore,
    IUserRoleStore<RtUser> userRoleStore,
    ILogger<DelegatedIdentityResolver> logger) : IDelegatedIdentityResolver
{
    /// <inheritdoc />
    public async Task<DelegatedIdentityResult> ResolveAsync(
        string serviceAccountClientId,
        string userSubjectId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(serviceAccountClientId))
        {
            return DelegatedIdentityResult.Denied(DelegationDenialReason.ServiceAccountNotFound);
        }

        if (string.IsNullOrWhiteSpace(userSubjectId))
        {
            return DelegatedIdentityResult.Denied(DelegationDenialReason.UserNotFound);
        }

        // --- Service-account side -------------------------------------------------------------
        var rtClient = await clientStore.FindRtClientByIdAsync(serviceAccountClientId);
        if (rtClient == null)
        {
            logger.LogWarning(
                "Delegation denied: service-account client '{ClientId}' does not exist in the request tenant",
                serviceAccountClientId);
            return DelegatedIdentityResult.Denied(DelegationDenialReason.ServiceAccountNotFound);
        }

        var serviceAccountRoles = await clientRoleStore.GetEffectiveRoleNamesAsync(rtClient.RtId);

        // --- User side ------------------------------------------------------------------------
        // A malformed subject identifier (not an RtId) is an unknown user, not a server fault — the
        // store's id conversion throws for it, so it is folded into the same denial.
        RtUser? user;
        try
        {
            user = await userRoleStore.FindByIdAsync(userSubjectId, cancellationToken);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            logger.LogWarning(
                "Delegation denied: subject '{UserSubjectId}' is not a valid user identifier", userSubjectId);
            return DelegatedIdentityResult.Denied(DelegationDenialReason.UserNotFound);
        }

        if (user == null)
        {
            logger.LogWarning(
                "Delegation denied: user '{UserSubjectId}' does not exist in the request tenant", userSubjectId);
            return DelegatedIdentityResult.Denied(DelegationDenialReason.UserNotFound);
        }

        var userRoles = await userRoleStore.GetRolesAsync(user, cancellationToken);

        // --- Intersection ---------------------------------------------------------------------
        var serviceAccountRoleSet = new HashSet<string>(serviceAccountRoles, StringComparer.OrdinalIgnoreCase);
        var userRoleSet = new HashSet<string>(userRoles, StringComparer.OrdinalIgnoreCase);

        var effective = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var userRole in userRoleSet)
        {
            if (serviceAccountRoleSet.Contains(userRole))
            {
                effective.Add(userRole);
            }
        }

        // An empty intersection is NOT an error: the token is issued without role claims, which makes
        // every role-gated consumer fail closed. Logged at warning because it is almost always a
        // misconfiguration of the service account's role set.
        if (effective.Count == 0)
        {
            logger.LogWarning(
                "Delegation resolved with an EMPTY role intersection: service account '{ClientId}' ({ServiceAccountRoleCount} role(s)) acting for user '{UserSubjectId}' ({UserRoleCount} role(s)) — the delegated token will carry no role claims",
                serviceAccountClientId, serviceAccountRoleSet.Count, userSubjectId, userRoleSet.Count);
        }
        else
        {
            logger.LogInformation(
                "Delegation resolved: service account '{ClientId}' acting for user '{UserSubjectId}' — {EffectiveRoleCount} effective role(s) from {ServiceAccountRoleCount} ∩ {UserRoleCount}",
                serviceAccountClientId, userSubjectId, effective.Count, serviceAccountRoleSet.Count,
                userRoleSet.Count);
        }

        return DelegatedIdentityResult.Granted(effective, serviceAccountRoleSet, userRoleSet);
    }
}
