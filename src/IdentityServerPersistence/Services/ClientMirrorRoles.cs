using System.Collections.Concurrent;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services;

/// <summary>
///     The rules of the mirror role list (System.Identity 3.9.0): which roles of
///     <c>Client.MirrorRoleNames</c> may be mirrored and which clients may carry a list.
/// </summary>
public static class ClientMirrorRoleRules
{
    /// <summary>The grant type a client needs to carry a list: only a client-credentials token ever uses a mirror's roles.</summary>
    public const string ClientCredentialsGrantType = "client_credentials";

    /// <summary>
    ///     Roles that are never mirrored (decided by the platform owner): they administer the tenant, its users, its secrets, the
    ///     platform or the AI budget, so a mirrored copy would make one client an administrator of every child tenant.
    /// </summary>
    public static readonly IReadOnlySet<string> DeniedRoleNames = new HashSet<string>(
        [
            CommonConstants.TenantManagementRole,
            CommonConstants.UserManagementRole,
            CommonConstants.SecretManagementRole,
            "AdminPanelManagement",
            IdentityServiceConstants.AiBudgetAdminRole
        ],
        StringComparer.OrdinalIgnoreCase);

    /// <summary><c>true</c> when the role name may never be mirrored (case-insensitive, trimmed).</summary>
    public static bool IsDenied(string? roleName) =>
        !string.IsNullOrWhiteSpace(roleName) && DeniedRoleNames.Contains(roleName.Trim());

    /// <summary>
    ///     <c>true</c> for a confidential client that may use the client-credentials grant: it requires a secret and lists
    ///     <c>client_credentials</c>. A public client (Studio, octo-cli) never gets roles through its mirrors.
    /// </summary>
    public static bool MayCarryMirrorRoles(RtClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return client.RequireClientSecret &&
               (client.AllowedGrantTypes ?? Enumerable.Empty<string>()).Any(g =>
                   string.Equals(g, ClientCredentialsGrantType, StringComparison.Ordinal));
    }

    /// <summary>
    ///     The roles identity assigns on the mirrors of <paramref name="client" />: its list without blanks, duplicates and
    ///     denied names, or nothing when the client may not carry a list. Defence in depth: the method refuses such a list
    ///     before it is stored, this keeps a list that reached the store another way (a restored database) harmless.
    /// </summary>
    public static IReadOnlyList<string> DesiredRoleNames(RtClient client, IEnumerable<string>? roleNames = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (!MayCarryMirrorRoles(client))
        {
            return [];
        }

        return Normalize(roleNames ?? client.MirrorRoleNames ?? Enumerable.Empty<string>())
            .Where(n => !IsDenied(n))
            .ToList();
    }

    /// <summary>Trimmed, non-blank, distinct (case-insensitive) names in their first spelling.</summary>
    public static IReadOnlyList<string> Normalize(IEnumerable<string?> names)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var name in names)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var trimmed = name.Trim();
            if (seen.Add(trimmed))
            {
                result.Add(trimmed);
            }
        }

        return result;
    }
}

/// <summary>
///     The stored mirror role list of a client is not the one the caller judged its change against: another writer changed it
///     in between. Nothing was written.
/// </summary>
public sealed class ClientMirrorRolesChangedException(string clientId)
    : InvalidOperationException($"The mirror role list of client '{clientId}' was changed concurrently.");

/// <summary>The per-mirror outcome of a role reconciliation.</summary>
public enum MirrorRoleOutcome
{
    /// <summary>Nothing had to change.</summary>
    InSync,

    /// <summary>Roles or the tracking were written.</summary>
    Applied,

    /// <summary>Dry run: the plan was computed, nothing was written.</summary>
    Planned,

    /// <summary>No mirror of this parent in the child tenant (or the child tenant is unreachable).</summary>
    Skipped,

    /// <summary>A write failed; the next reconciliation pass retries it.</summary>
    Failed
}

/// <summary>What a role reconciliation did (or would do) on one mirror. Role names only, never a secret.</summary>
public sealed record MirrorRoleTenantResult(
    string ChildTenantId,
    MirrorRoleOutcome Outcome,
    IReadOnlyList<string> Added,
    IReadOnlyList<string> Removed,
    IReadOnlyList<string> AlreadyPresent,
    IReadOnlyList<string> Adopted,
    IReadOnlyList<string> HandSet,
    IReadOnlyList<string> RoleMissing,
    IReadOnlyList<string> Declined)
{
    public static MirrorRoleTenantResult Empty(string childTenantId, MirrorRoleOutcome outcome) =>
        new(childTenantId, outcome, [], [], [], [], [], [], []);
}

/// <summary>Result of a role reconciliation over every tracked mirror of one client.</summary>
public sealed record ClientMirrorRolesResult(
    IReadOnlyList<string> RoleNames,
    bool DryRun,
    IReadOnlyList<MirrorRoleTenantResult> Tenants);

/// <summary>
///     The plan of one mirror: pure, so the rules are unit-tested without a database. All comparisons of role names
///     are case-insensitive (role names are normalized upper-case in the store).
/// </summary>
/// <param name="Add">Role names to assign (canonical spelling of the child's role).</param>
/// <param name="Remove">Role names to take away (managed, no longer listed).</param>
/// <param name="AlreadyPresent">Listed roles the mirror holds (adopted ones included).</param>
/// <param name="Adopted">Listed roles the mirror held unmanaged; managed from now on.</param>
/// <param name="HandSet">Roles of the mirror the list does not name and identity does not manage.</param>
/// <param name="RoleMissing">Listed roles that do not exist in the child.</param>
/// <param name="Declined">Listed roles the tenant removed from this mirror; not assigned again.</param>
/// <param name="NewlyDeclined">Of <paramref name="Declined" />: the roles this pass found removed (audited once).</param>
/// <param name="Managed">ManagedRoleNames after the pass.</param>
/// <param name="DeclinedAfter">DeclinedRoleNames after the pass.</param>
public sealed record MirrorRolePlan(
    IReadOnlyList<string> Add,
    IReadOnlyList<string> Remove,
    IReadOnlyList<string> AlreadyPresent,
    IReadOnlyList<string> Adopted,
    IReadOnlyList<string> HandSet,
    IReadOnlyList<string> RoleMissing,
    IReadOnlyList<string> Declined,
    IReadOnlyList<string> NewlyDeclined,
    IReadOnlyList<string> Managed,
    IReadOnlyList<string> DeclinedAfter)
{
    /// <summary><c>true</c> when a role edge must be written.</summary>
    public bool ChangesRoles => Add.Count > 0 || Remove.Count > 0;

    /// <summary>
    ///     Computes the plan of one mirror.
    /// </summary>
    /// <param name="desired">The list of the original after <see cref="ClientMirrorRoleRules.DesiredRoleNames" />.</param>
    /// <param name="childRoleNames">Every role name that exists in the child tenant.</param>
    /// <param name="current">The names of the mirror's direct roles in the child tenant.</param>
    /// <param name="managed">ManagedRoleNames of the tracking row.</param>
    /// <param name="declined">DeclinedRoleNames of the tracking row.</param>
    /// <param name="sameMirror">
    ///     <c>true</c> when the tracking row refers to this mirror (ManagedMirrorRtId is its rtId). A re-created mirror starts
    ///     over: nothing it lacks counts as declined, and it is granted again.
    /// </param>
    public static MirrorRolePlan Compute(IReadOnlyList<string> desired, IEnumerable<string> childRoleNames,
        IEnumerable<string> current, IEnumerable<string>? managed, IEnumerable<string>? declined, bool sameMirror)
    {
        var comparer = StringComparer.OrdinalIgnoreCase;
        var existing = new Dictionary<string, string>(comparer);
        foreach (var name in childRoleNames.Where(n => !string.IsNullOrWhiteSpace(n)))
        {
            existing.TryAdd(name.Trim(), name.Trim());
        }

        var currentSet = new HashSet<string>(current.Where(n => !string.IsNullOrWhiteSpace(n)), comparer);
        var desiredSet = new HashSet<string>(desired, comparer);
        var managedBefore = sameMirror
            ? new HashSet<string>(ClientMirrorRoleRules.Normalize(managed ?? []), comparer)
            : new HashSet<string>(comparer);
        var declinedSet = sameMirror
            ? new HashSet<string>(ClientMirrorRoleRules.Normalize(declined ?? []), comparer)
            : new HashSet<string>(comparer);

        // A declined role the mirror holds again was given back by the tenant: it is no longer declined.
        declinedSet.RemoveWhere(currentSet.Contains);

        // A listed role identity managed and the mirror lost on the same mirror was removed by the tenant: declined. A role
        // whose definition is gone from the child was not declined: it is missing, and assigned again once it exists.
        var newlyDeclined = managedBefore
            .Where(r => desiredSet.Contains(r) && !currentSet.Contains(r) && existing.ContainsKey(r))
            .Order(comparer).ToList();
        declinedSet.UnionWith(newlyDeclined);

        // Managed roles the mirror no longer holds are no longer managed (declined, or removed while not listed).
        var managedAfter = new HashSet<string>(managedBefore.Where(currentSet.Contains), comparer);

        var add = new List<string>();
        var present = new List<string>();
        var adopted = new List<string>();
        var missing = new List<string>();
        var declinedListed = new List<string>();
        foreach (var name in desired)
        {
            if (!existing.TryGetValue(name, out var canonical))
            {
                missing.Add(name);
                continue;
            }

            if (declinedSet.Contains(canonical))
            {
                declinedListed.Add(canonical);
                continue;
            }

            if (currentSet.Contains(canonical))
            {
                present.Add(canonical);
                if (managedAfter.Add(canonical))
                {
                    adopted.Add(canonical);
                }

                continue;
            }

            add.Add(canonical);
            managedAfter.Add(canonical);
        }

        var remove = managedAfter.Where(r => !desiredSet.Contains(r)).Order(comparer).ToList();
        managedAfter.ExceptWith(remove);

        var handSet = currentSet.Where(r => !desiredSet.Contains(r) && !managedBefore.Contains(r))
            .Order(comparer).ToList();

        return new MirrorRolePlan(add, remove, present, adopted, handSet, missing, declinedListed, newlyDeclined,
            managedAfter.Order(comparer).ToList(), declinedSet.Order(comparer).ToList());
    }
}

/// <summary>
///     Assigns the roles of <c>Client.MirrorRoleNames</c> to the tracked mirrors of a client. Runs in the server's
///     system context after every mirror convergence (tenant setup, provisioning methods, update of the original, the
///     periodic reconciliation) and for <c>Client.SetMirrorRoles-1</c>.
/// </summary>
/// <remarks>
///     <para>
///         <b>Only tracked mirrors.</b> A role goes only to the client of the child tenant that carries this parent's mirror
///         marker and has a tracking row of this parent; a client of the same id without them (a stray copy from a restored
///         database, the child's own client) gets nothing.
///     </para>
///     <para>
///         <b>Only what identity manages is removed.</b> The tracking row records the managed roles, the roles the tenant
///         declined and the mirror rtId both refer to. Hand-set roles are never removed; a listed role a mirror already holds
///         is adopted. A managed role that a tenant administrator removed from the same mirror is recorded as declined and
///         not assigned again; a re-created mirror (another rtId) is granted again.
///     </para>
///     <para>
///         <b>Order and concurrency.</b> The row is read first, then the child; the role edges are written before the row,
///         and the row with the version it was read with. A concurrent writer makes the row write fail; the next pass
///         converges (an added edge without its row write is adopted, a removed one is forgotten). Never a secret in a log or
///         audit event: role names, client id and tenant ids only.
///     </para>
/// </remarks>
internal sealed class ClientMirrorRoleReconciler(ILogger logger, IEventRepository? eventRepository)
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    /// <summary>
    ///     Test seam: runs after the child roles were written and before the tracking row is written (arguments: client id,
    ///     child tenant id). A throw here simulates a failed write between the two steps.
    /// </summary>
    internal Func<string, string, Task>? BeforeRowWriteForTests { get; set; }

    /// <summary>
    ///     Reconciles the roles of one tracked mirror. Never throws for a failed write when <paramref name="swallowErrors" />
    ///     is set: the failure is logged (ERROR, names only) and reported as <see cref="MirrorRoleOutcome.Failed" />.
    /// </summary>
    public async Task<MirrorRoleTenantResult> ReconcileAsync(ITenantRepository parentRepo, IOctoSession parentSession,
        string parentTenantId, string clientId, string childTenantId, ITenantRepository? childRepo,
        IReadOnlyList<string>? plannedRoleNames, bool dryRun, bool swallowErrors = true, RtClient? parentClient = null)
    {
        var gate = Locks.GetOrAdd($"{parentTenantId}|{clientId}|{childTenantId}".ToLowerInvariant(),
            _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await ReconcileCoreAsync(parentRepo, parentSession, parentTenantId, clientId, childTenantId, childRepo,
                plannedRoleNames, dryRun, parentClient).ConfigureAwait(false);
        }
        catch (Exception ex) when (swallowErrors && ex is not OperationCanceledException)
        {
            logger.LogError(ex,
                "Mirror role reconciliation failed for clientId='{ClientId}' parent='{ParentTenantId}' child='{ChildTenantId}'; retried by the next mirror reconciliation pass",
                clientId, parentTenantId, childTenantId);
            return MirrorRoleTenantResult.Empty(childTenantId, MirrorRoleOutcome.Failed);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<MirrorRoleTenantResult> ReconcileCoreAsync(ITenantRepository parentRepo,
        IOctoSession parentSession, string parentTenantId, string clientId, string childTenantId,
        ITenantRepository? childRepo, IReadOnlyList<string>? plannedRoleNames, bool dryRun, RtClient? parentClient)
    {
        // 1. The row first: a role edge written by another writer after this read makes the row write below fail.
        var row = (await parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(parentSession, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId)))
            .Items.FirstOrDefault(r => string.Equals(r.ParentClientId, clientId, StringComparison.Ordinal) &&
                                       string.Equals(r.ChildTenantId, childTenantId,
                                           StringComparison.OrdinalIgnoreCase));
        if (row == null || childRepo == null)
        {
            return MirrorRoleTenantResult.Empty(childTenantId, MirrorRoleOutcome.Skipped);
        }

        // Cheap path for the common case, nothing listed and nothing tracked. The parent the caller read for the mirror
        // convergence of the same pass is only a hint for it: a stale hint with an empty list skips nothing that this pass
        // could have removed (nothing is tracked), and every other case reads the parent again below, inside the lock and
        // after the row, so a list that was just cleared is never applied from an older copy.
        var nothingTracked = IsEmpty(row.ManagedRoleNames) && IsEmpty(row.DeclinedRoleNames);
        if (nothingTracked && plannedRoleNames == null && parentClient is not null &&
            string.Equals(parentClient.ClientId, clientId, StringComparison.Ordinal) &&
            ClientMirrorRoleRules.DesiredRoleNames(parentClient).Count == 0)
        {
            return MirrorRoleTenantResult.Empty(childTenantId, dryRun ? MirrorRoleOutcome.Planned : MirrorRoleOutcome.InSync);
        }

        var parent = (await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(parentSession, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId)))
            .Items.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));
        var desired = parent == null ? [] : ClientMirrorRoleRules.DesiredRoleNames(parent, plannedRoleNames);
        if (desired.Count == 0 && nothingTracked)
        {
            return MirrorRoleTenantResult.Empty(childTenantId, dryRun ? MirrorRoleOutcome.Planned : MirrorRoleOutcome.InSync);
        }

        using var childSession = await childRepo.GetSessionAsync().ConfigureAwait(false);
        var mirror = await FindTrackedMirrorAsync(childRepo, childSession, parentTenantId, clientId).ConfigureAwait(false);
        if (mirror == null)
        {
            return MirrorRoleTenantResult.Empty(childTenantId, MirrorRoleOutcome.Skipped);
        }

        var roles = (await childRepo.GetRtEntitiesByTypeAsync<RtRole>(childSession, RtEntityQueryOptions.Create())
                .ConfigureAwait(false)).Items
            .Where(r => !string.IsNullOrWhiteSpace(r.Name)).ToList();
        var roleByName = new Dictionary<string, RtRole>(StringComparer.OrdinalIgnoreCase);
        var nameById = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var role in roles)
        {
            roleByName.TryAdd(role.Name!.Trim(), role);
            nameById[role.RtId.ToString()] = role.Name!.Trim();
        }

        var edges = (await childRepo.GetRtAssociationsAsync(childSession, mirror.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId)).ConfigureAwait(false)).Items.ToList();
        var current = edges.Select(e => nameById.GetValueOrDefault(e.TargetRtId.ToString()))
            .Where(n => n != null).Select(n => n!).ToList();

        var sameMirror = string.Equals(row.ManagedMirrorRtId, mirror.RtId.ToString(), StringComparison.Ordinal);
        var plan = MirrorRolePlan.Compute(desired, roleByName.Keys, current, row.ManagedRoleNames,
            row.DeclinedRoleNames, sameMirror);

        if (plan.RoleMissing.Count > 0)
        {
            logger.LogWarning(
                "Mirror roles of clientId='{ClientId}' in child '{ChildTenantId}': role(s) {RoleNames} do not exist there; assigned once they exist",
                clientId, childTenantId, string.Join(",", plan.RoleMissing));
        }

        var rowChanged = !SameSet(plan.Managed, row.ManagedRoleNames) ||
                         !SameSet(plan.DeclinedAfter, row.DeclinedRoleNames) ||
                         (!sameMirror && (plan.Managed.Count > 0 || plan.DeclinedAfter.Count > 0 ||
                                          row.ManagedMirrorRtId != null));
        if (dryRun)
        {
            return ToResult(childTenantId, MirrorRoleOutcome.Planned, plan);
        }

        if (!plan.ChangesRoles && !rowChanged)
        {
            return ToResult(childTenantId, MirrorRoleOutcome.InSync, plan);
        }

        // 2. The edges in the child, in one transaction.
        if (plan.ChangesRoles)
        {
            var mirrorId = mirror.ToRtEntityId();
            var updates = new List<AssociationUpdateInfo>();
            updates.AddRange(plan.Add.Select(n => AssociationUpdateInfo.CreateInsert(mirrorId,
                roleByName[n].ToRtEntityId(), IdentityAssociationConstants.AssignedRoleId)));
            foreach (var name in plan.Remove)
            {
                var role = roleByName.GetValueOrDefault(name);
                var edge = role == null ? null : edges.FirstOrDefault(e => e.TargetRtId.Equals(role.RtId));
                if (edge != null)
                {
                    updates.Add(AssociationUpdateInfo.CreateDelete(mirrorId,
                        new RtEntityId(edge.TargetCkTypeId, edge.TargetRtId), IdentityAssociationConstants.AssignedRoleId));
                }
            }

            if (updates.Count > 0)
            {
                childSession.StartTransaction();
                var opResult = new OperationResult();
                await childRepo.ApplyChangesAsync(childSession, updates, opResult).ConfigureAwait(false);
                if (opResult.HasErrors || opResult.HasFatalErrors)
                {
                    await childSession.AbortTransactionAsync().ConfigureAwait(false);
                    throw new InvalidOperationException(
                        $"Writing the mirror roles of client '{clientId}' in tenant '{childTenantId}' failed: " +
                        string.Join("; ", opResult.GetMessages()));
                }

                await childSession.CommitTransactionAsync().ConfigureAwait(false);
            }
        }

        if (BeforeRowWriteForTests != null)
        {
            await BeforeRowWriteForTests(clientId, childTenantId).ConfigureAwait(false);
        }

        // 3. The row, version-checked. A conflict means another writer was faster; the next pass converges.
        row.ManagedRoleNames = new AttributeStringValueList(plan.Managed.ToList());
        row.DeclinedRoleNames = new AttributeStringValueList(plan.DeclinedAfter.ToList());
        row.ManagedMirrorRtId = mirror.RtId.ToString();
        try
        {
            await parentRepo.ReplaceOneRtEntityByIdAsync(parentSession, row.RtId, row, row.RtVersion)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is RtVersionConflictException or EntityNotFoundException)
        {
            logger.LogDebug(
                "Mirror role tracking of clientId='{ClientId}' child='{ChildTenantId}' changed concurrently; the next pass converges",
                clientId, childTenantId);
        }

        await AuditAsync(childTenantId, clientId, parentTenantId, plan).ConfigureAwait(false);
        return ToResult(childTenantId, MirrorRoleOutcome.Applied, plan);
    }

    private static async Task<RtClient?> FindTrackedMirrorAsync(ITenantRepository childRepo, IOctoSession childSession,
        string parentTenantId, string clientId)
    {
        var mirrors = (await childRepo.GetRtEntitiesByTypeAsync<RtClient>(childSession, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId)).ConfigureAwait(false))
            .Items.Where(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal) &&
                              string.Equals(c.ProvisionedByParentTenantId, parentTenantId,
                                  StringComparison.OrdinalIgnoreCase))
            .ToList();
        return mirrors.Count == 0 ? null : ClientMirrorProvisioningService.SelectCanonicalMirror(mirrors);
    }

    private async Task AuditAsync(string childTenantId, string clientId, string parentTenantId, MirrorRolePlan plan)
    {
        var messages = new List<string>();
        if (plan.Add.Count > 0)
        {
            messages.Add($"Mirror roles granted: client '{clientId}' (mirror of tenant '{parentTenantId}') was given role(s) " +
                         $"{string.Join(", ", plan.Add)} in tenant '{childTenantId}' because the original lists them " +
                         "(Client.MirrorRoleNames)");
        }

        if (plan.Remove.Count > 0)
        {
            messages.Add($"Mirror roles removed: role(s) {string.Join(", ", plan.Remove)} were taken from client " +
                         $"'{clientId}' (mirror of tenant '{parentTenantId}') in tenant '{childTenantId}' because the " +
                         "original no longer lists them");
        }

        if (plan.Adopted.Count > 0)
        {
            messages.Add($"Mirror roles adopted: role(s) {string.Join(", ", plan.Adopted)} of client '{clientId}' in tenant " +
                         $"'{childTenantId}' are managed by the mirror role list of tenant '{parentTenantId}' from now on");
        }

        if (plan.NewlyDeclined.Count > 0)
        {
            messages.Add($"Mirror roles declined: role(s) {string.Join(", ", plan.NewlyDeclined)} were removed from client " +
                         $"'{clientId}' (mirror of tenant '{parentTenantId}') in tenant '{childTenantId}' by the tenant; " +
                         "identity does not assign them again");
            logger.LogWarning(
                "Mirror roles {RoleNames} of clientId='{ClientId}' were removed in tenant '{ChildTenantId}' by the tenant; recorded as declined, not assigned again",
                string.Join(",", plan.NewlyDeclined), clientId, childTenantId);
        }

        foreach (var message in messages)
        {
            logger.LogInformation("{Message}", message);
            if (eventRepository == null)
            {
                continue;
            }

            try
            {
                await eventRepository.StoreInformationEvent(childTenantId, RtEventSourcesEnum.IdentityService, message)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to persist the mirror role audit event to the event log of tenant '{TenantId}'",
                    childTenantId);
            }

            try
            {
                await eventRepository.StoreSystemInformationEvent(RtEventSourcesEnum.IdentityService, message)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to persist the mirror role audit event to the system event log");
            }
        }
    }

    private static MirrorRoleTenantResult ToResult(string childTenantId, MirrorRoleOutcome outcome, MirrorRolePlan plan) =>
        new(childTenantId, outcome, plan.Add, plan.Remove, plan.AlreadyPresent, plan.Adopted, plan.HandSet,
            plan.RoleMissing, plan.Declined);

    private static bool IsEmpty(IEnumerable<string>? names) => names == null || !names.Any();

    private static bool SameSet(IEnumerable<string> left, IEnumerable<string>? right) =>
        new HashSet<string>(left, StringComparer.OrdinalIgnoreCase).SetEquals(right ?? []);
}
