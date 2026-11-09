namespace IdentityServerPersistence.Services.PipelineServiceAccounts;

/// <summary>A role every pipeline service account holds, granted by identity itself.</summary>
/// <param name="RoleName">The role name (as seeded by <c>System.Identity.Bootstrap</c>).</param>
/// <param name="RequiresFilesModel">
///     True when the tenant-setup pass grants the role only to tenants with System.Files in their CK cache.
/// </param>
public sealed record PipelineServiceAccountBaselineRole(string RoleName, bool RequiresFilesModel);

/// <summary>
///     The single list of roles identity grants to every pipeline service account (client id with the
///     <see cref="IdentityServiceConstants.PipelineServiceAccountClientIdPrefix"/> prefix, case-sensitive), both in the
///     identity-data command (<c>CreateIdentityDataCommandRequestConsumer</c>) and at every tenant setup
///     (<see cref="PipelineServiceAccountRoleGrant"/>). A role is only granted when it is seeded in the tenant.
/// </summary>
/// <remarks>
///     <list type="bullet">
///         <item>
///             <c>FileManagement</c> (AB#6467 / AB#6457): the file nodes run in the adapter's engine, where the
///             System.Files data policies apply to the account's roles.
///         </item>
///         <item>
///             <c>StreamDataReader</c> (AB#8581): the asset repository gates stream-data reads on a StreamData role
///             (AB#8559). The Communication Controller adds it to declarative accounts on reconcile (AB#8563), but it
///             cannot add a role to a legacy account (no <c>AssignedRoleNames</c>) without removing the others, so
///             identity grants it — additively — to every account.
///         </item>
///     </list>
///     The grant is a system grant, not a user's role change, so it does not run through the role change guard.
/// </remarks>
public static class PipelineServiceAccountBaselineRoles
{
    public static IReadOnlyList<PipelineServiceAccountBaselineRole> All { get; } =
    [
        new(IdentityServiceConstants.FileManagementRole, RequiresFilesModel: true),
        new(IdentityServiceConstants.StreamDataReaderRole, RequiresFilesModel: false)
    ];

    /// <summary>The role names the tenant-setup pass grants in a tenant with or without System.Files.</summary>
    public static IReadOnlyList<string> ForTenantSetup(bool tenantHasFilesModel) =>
        All.Where(r => tenantHasFilesModel || !r.RequiresFilesModel).Select(r => r.RoleName).ToList();

    /// <summary>
    ///     The role names the identity-data command grants. All of them: the command has no CK cache probe and has always
    ///     granted <c>FileManagement</c> whenever the role is seeded.
    /// </summary>
    public static IReadOnlyList<string> ForIdentityDataCommand() => All.Select(r => r.RoleName).ToList();

    /// <summary>True for a client id under the pipeline service account prefix (ordinal, case-sensitive).</summary>
    public static bool IsPipelineServiceAccount(string? clientId) =>
        clientId != null &&
        clientId.StartsWith(IdentityServiceConstants.PipelineServiceAccountClientIdPrefix, StringComparison.Ordinal);
}
