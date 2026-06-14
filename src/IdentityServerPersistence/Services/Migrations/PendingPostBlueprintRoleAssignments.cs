namespace IdentityServerPersistence.Services.Migrations;

/// <summary>
/// DTO persisted in <c>SystemConfiguration[PendingPostBlueprintRoleAssignmentsKey]</c> by the
/// <see cref="PreBlueprintCleanupMigration"/> for the
/// <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> post-blueprint restore step.
/// </summary>
/// <remarks>
/// <para>
/// The two-phase preservation needed for Phase 3 PR #4:
/// </para>
/// <list type="number">
///   <item>Pre-blueprint phase (in the migration): walk every <c>RtUser</c> and
///     <c>RtExternalTenantUserMapping</c>, read their outbound <c>AssignedRole</c> edges, look
///     up each OLD <c>RtRole</c>'s <c>Name</c> attribute, and stash the resulting <c>(origin rtId
///     → role-name list)</c> map here. Then delete the OLD entities and orphan associations.</item>
///   <item>Post-blueprint phase (in <c>SetupTenantAsync</c>, after
///     <c>ApplyServiceManagedBlueprintsAsync</c>): for each captured origin + role-name, look up
///     the NEW (blueprint-installed) <c>RtRole</c> by name, and create a fresh
///     <c>AssignedRole</c> edge against its stable rtId in the <c>660…01..0E</c> range.</item>
/// </list>
/// <para>
/// Persisting the map in a TenantConfiguration row instead of holding it in a C# local lets the
/// pipeline survive a crash between phase 1 and phase 2 — if Identity goes down between the
/// entity deletes and the blueprint apply, the next startup still has the captured map and can
/// resume the restore.
/// </para>
/// <para>
/// Keys are <see cref="Meshmakers.Octo.ConstructionKit.Contracts.OctoObjectId"/> hex strings so
/// the DTO round-trips cleanly through the
/// <c>SystemConfiguration.configurationValue</c> JSON column without a custom converter.
/// </para>
/// </remarks>
public sealed class PendingPostBlueprintRoleAssignments
{
    /// <summary>
    /// Map from <c>RtUser</c> hex rtId to the list of role names the user held before the
    /// blueprint cutover. Empty when no user had any assignments.
    /// </summary>
    public Dictionary<string, List<string>> UserRoles { get; set; } = new();

    /// <summary>
    /// Map from <c>RtExternalTenantUserMapping</c> hex rtId to the list of role names the
    /// mapping held before the cutover. Empty when no mapping had any.
    /// </summary>
    public Dictionary<string, List<string>> ExternalMappingRoles { get; set; } = new();
}
