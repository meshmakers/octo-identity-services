using IdentityServerPersistence.Services.RoleGrants;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.SecretManagement;

/// <summary>
///     Marker persisted in the tenant configuration once <see cref="SecretManagementAdminGrant"/> has run for a
///     tenant. Its presence is the run-once gate: an operator who later removes the role from an administrator
///     must not see it come back on the next restart. Same document shape as before AB#8690 (the base class carries
///     the properties).
/// </summary>
public sealed class SecretManagementAdminGrantMarker : AdministratorRoleGrantMarker;

/// <summary>Outcome of one <see cref="SecretManagementAdminGrant.EnsureAsync"/> call.</summary>
internal enum SecretManagementAdminGrantStatus
{
    /// <summary>The grants were written (possibly none) and the marker recorded.</summary>
    Completed,

    /// <summary>The marker already existed; nothing was read or written.</summary>
    AlreadyDone,

    /// <summary>The SecretManagement role does not exist (yet); nothing written, no marker — retried next setup.</summary>
    RoleMissing
}

internal sealed record SecretManagementAdminGrantResult(
    SecretManagementAdminGrantStatus Status,
    IReadOnlyList<string> GrantedUserIds);

/// <summary>
///     AB#5544: one-time, additive grant of the <c>SecretManagement</c> role to the existing HUMAN administrators
///     of a tenant — every local user that holds both <c>AdminPanelManagement</c> and <c>TenantManagement</c>.
///     No group, client or cross-tenant shadow user receives it. See <see cref="SecretManagementGrantPlanner"/>.
/// </summary>
/// <remarks>
///     <para>
///         Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> right AFTER the
///         <c>System.Identity.Bootstrap</c> blueprint apply, because the role (660…60, blueprint 1.7.0) has to
///         exist first. That is why this is not an <c>IMigration</c>: the infrastructure migrations run before
///         the blueprint apply.
///     </para>
///     <para>
///         Never removes anything. Only <c>AssignedRole</c> insert edges are written, and only for subjects
///         that do not hold the role yet. The marker
///         (<see cref="IdentityServiceConstants.SecretManagementAdminGrantKey"/>) is written after the edges
///         are committed; a crash in between re-runs the step, which then finds the edges and writes nothing
///         new.
///     </para>
///     <para>
///         Since AB#8690 the steps live in <see cref="AdministratorRoleOneTimeGrant"/>, shared with the
///         <c>AiBudgetAdmin</c> grant of the system tenant; this class keeps the role, the marker and the result types.
///     </para>
/// </remarks>
internal static class SecretManagementAdminGrant
{
    public static async Task<SecretManagementAdminGrantResult> EnsureAsync(
        ITenantContext tenantContext, ILogger logger)
    {
        var result = await AdministratorRoleOneTimeGrant.EnsureAsync<SecretManagementAdminGrantMarker>(
            tenantContext, CommonConstants.SecretManagementRole, IdentityServiceConstants.SecretManagementAdminGrantKey,
            logger).ConfigureAwait(false);

        var status = result.Status switch
        {
            AdministratorRoleGrantStatus.Completed => SecretManagementAdminGrantStatus.Completed,
            AdministratorRoleGrantStatus.AlreadyDone => SecretManagementAdminGrantStatus.AlreadyDone,
            AdministratorRoleGrantStatus.RoleMissing => SecretManagementAdminGrantStatus.RoleMissing,
            _ => throw new InvalidOperationException($"Unexpected grant status {result.Status}.")
        };
        return new SecretManagementAdminGrantResult(status, result.GrantedUserIds);
    }
}
