using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the child group methods (declared in <c>ck-group.yaml</c>, System.Identity 3.3.0).</summary>
internal static class GroupChildGroupErrors
{
    public const string ChildGroupNotFound = "CHILD_GROUP_NOT_FOUND";
    public const string ChildGroupAlreadyInGroup = "CHILD_GROUP_ALREADY_IN_GROUP";
    public const string ChildGroupNotInGroup = "CHILD_GROUP_NOT_IN_GROUP";
    public const string GroupCycle = "GROUP_CYCLE";

    /// <summary>Parameter of a <c>GROUP_CYCLE</c> answer: <see cref="CycleSelf" /> or <see cref="CycleDescendant" />.</summary>
    public const string CycleKindParameter = "cycle";

    /// <summary>The group would become a member of itself.</summary>
    public const string CycleSelf = "self";

    /// <summary>The group is reachable from the child group through its child groups.</summary>
    public const string CycleDescendant = "descendant";
}

/// <summary>
///     Shared flow of <c>Group.AddChildGroup</c> and <c>Group.RemoveChildGroup</c> (System.Identity 3.3.0): the rules of the
///     REST endpoints <c>PUT/DELETE system/v1/groups/{group}/members/groups/{child}</c>, which are their facades.
/// </summary>
/// <remarks>
///     The child group is named by its rtId. One that is not an object id, does not exist or that the caller cannot read
///     is <c>CHILD_GROUP_NOT_FOUND</c>; removing a child group of the group that the caller cannot read is
///     <c>METHOD_FORBIDDEN</c> (<c>reason</c> = <c>data-permission</c>). Adding and removing a child group runs the role
///     change guard (<see cref="RoleGraphChange.MemberAdded" /> / <see cref="RoleGraphChange.MemberRemoved" /> with
///     <see cref="GroupMemberKind.Group" />): the members of the child group inherit the roles of the group. The audit event
///     carries <c>memberKind</c> <c>Group</c> and <c>memberId</c>.
/// </remarks>
internal abstract class GroupChildGroupHandlerBase<TParameters>(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<TParameters>(services) where TParameters : class
{
    /// <summary>The child group id parameter.</summary>
    protected abstract string? ChildGroupId(TParameters parameters);

    /// <summary>
    ///     Applies the change; the group exists, the child id is an object id. <paramref name="child" /> is <c>null</c> for a
    ///     group that does not exist; <paramref name="readable" /> is <c>false</c> for one the caller cannot read.
    /// </summary>
    protected abstract Task<CkMethodOutcome> ApplyChildAsync(IdentityMethodCall call, IGroupStore groupStore, RtGroup group,
        OctoObjectId childId, RtGroup? child, bool isMember, bool readable, CancellationToken cancellationToken);

    protected sealed override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        TParameters parameters, CancellationToken cancellationToken)
    {
        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        var group = await groupStore.FindByIdAsync(targetRtId).ConfigureAwait(false);
        if (group == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var childGroupId = ChildGroupId(parameters)?.Trim();
        call.Details["memberKind"] = nameof(GroupMemberKind.Group);
        call.Details["memberId"] = childGroupId ?? string.Empty;
        if (string.IsNullOrEmpty(childGroupId) || !OctoObjectId.TryParse(childGroupId, out var childId))
        {
            return CkMethodOutcome.Fail(GroupChildGroupErrors.ChildGroupNotFound);
        }

        var child = await groupStore.FindByIdAsync(childId).ConfigureAwait(false);
        var readable = true;
        if (child != null)
        {
            var verdict = await call.EvaluateAsync(
                new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtGroup>(), child.RtId), RtDataAction.Read,
                cancellationToken).ConfigureAwait(false);
            readable = verdict.IsAllowed;
        }

        var memberIds = await groupStore.GetMemberGroupIdsAsync(group.RtId).ConfigureAwait(false);
        var isMember = memberIds.Contains(childId.ToString(), StringComparer.OrdinalIgnoreCase);
        return await ApplyChildAsync(call, groupStore, group, childId, child, isMember, readable, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Runs the role change guard on a change of the group graph; <c>null</c> when it is allowed.</summary>
    protected static async Task<CkMethodOutcome?> GuardAsync(IdentityMethodCall call, RoleGraphChange change,
        CancellationToken cancellationToken)
    {
        var decision = await call.Services.GetRequiredService<IRoleChangeGuard>()
            .EvaluateAsync(call.Caller, change, cancellationToken).ConfigureAwait(false);
        return decision.IsAllowed ? null : call.Refuse(decision);
    }
}

/// <summary>
///     Handler of <c>System.Identity/Group.AddChildGroup-1</c> (System.Identity 3.3.0): adds a group as a child group. Order of
///     the checks as in REST: group, child group, a group in itself, a cycle (the group reachable from the child through its
///     child groups), the role change guard. A child group that is already a member changes nothing
///     (<c>CHILD_GROUP_ALREADY_IN_GROUP</c>).
/// </summary>
internal sealed class GroupAddChildGroupHandler(IServiceProvider services)
    : GroupChildGroupHandlerBase<GroupAddChildGroupParameters>(services)
{
    protected override string? ChildGroupId(GroupAddChildGroupParameters parameters) => parameters.ChildGroupId;

    protected override async Task<CkMethodOutcome> ApplyChildAsync(IdentityMethodCall call, IGroupStore groupStore,
        RtGroup group, OctoObjectId childId, RtGroup? child, bool isMember, bool readable,
        CancellationToken cancellationToken)
    {
        // a group the caller cannot read answers like a missing one (its existence is not told)
        if (child == null || !readable)
        {
            return CkMethodOutcome.Fail(GroupChildGroupErrors.ChildGroupNotFound);
        }

        if (group.RtId == child.RtId)
        {
            return Cycle(call, GroupChildGroupErrors.CycleSelf);
        }

        if (isMember)
        {
            return CkMethodOutcome.Fail(GroupChildGroupErrors.ChildGroupAlreadyInGroup);
        }

        if (await GroupGraph.WouldCreateCycleAsync(groupStore, group.RtId, child.RtId).ConfigureAwait(false))
        {
            return Cycle(call, GroupChildGroupErrors.CycleDescendant);
        }

        var refusal = await GuardAsync(call,
            new RoleGraphChange.MemberAdded(group.RtId.ToString(), GroupMemberKind.Group, child.RtId.ToString()),
            cancellationToken).ConfigureAwait(false);
        if (refusal != null)
        {
            return refusal;
        }

        await groupStore.AddMemberGroupAsync(group.RtId, child.RtId.ToString()).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }

    private static CkMethodOutcome Cycle(IdentityMethodCall call, string kind)
    {
        call.Details[GroupChildGroupErrors.CycleKindParameter] = kind;
        return CkMethodOutcome.Fail(GroupChildGroupErrors.GroupCycle, (GroupChildGroupErrors.CycleKindParameter, kind));
    }
}

/// <summary>
///     Handler of <c>System.Identity/Group.RemoveChildGroup-1</c> (System.Identity 3.3.0): removes a child group. A child that
///     is not a member is <c>CHILD_GROUP_NOT_IN_GROUP</c>; an edge to a group that no longer exists is still removed.
/// </summary>
internal sealed class GroupRemoveChildGroupHandler(IServiceProvider services)
    : GroupChildGroupHandlerBase<GroupRemoveChildGroupParameters>(services)
{
    protected override string? ChildGroupId(GroupRemoveChildGroupParameters parameters) => parameters.ChildGroupId;

    protected override async Task<CkMethodOutcome> ApplyChildAsync(IdentityMethodCall call, IGroupStore groupStore,
        RtGroup group, OctoObjectId childId, RtGroup? child, bool isMember, bool readable,
        CancellationToken cancellationToken)
    {
        if (!isMember)
        {
            return readable
                ? CkMethodOutcome.Fail(GroupChildGroupErrors.ChildGroupNotInGroup)
                : CkMethodOutcome.Fail(GroupChildGroupErrors.ChildGroupNotFound);
        }

        // the membership is visible through the group: a child group the caller cannot read is refused, not silently kept
        if (!readable)
        {
            return call.NotPermitted();
        }

        var refusal = await GuardAsync(call,
            new RoleGraphChange.MemberRemoved(group.RtId.ToString(), GroupMemberKind.Group, childId.ToString()),
            cancellationToken).ConfigureAwait(false);
        if (refusal != null)
        {
            return refusal;
        }

        await groupStore.RemoveMemberGroupAsync(group.RtId, childId.ToString()).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>The nested-group graph rules shared by the methods.</summary>
internal static class GroupGraph
{
    /// <summary>
    ///     <c>true</c> when adding <paramref name="childGroupId" /> as a child of <paramref name="parentId" /> would create a
    ///     cycle: a depth-first walk over the child groups of the child reaches the parent.
    /// </summary>
    public static async Task<bool> WouldCreateCycleAsync(IGroupStore groupStore, OctoObjectId parentId,
        OctoObjectId childGroupId)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stack = new Stack<string>(await groupStore.GetMemberGroupIdsAsync(childGroupId).ConfigureAwait(false));
        var parent = parentId.ToString();
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if (string.Equals(current, parent, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!visited.Add(current) || !OctoObjectId.TryParse(current, out var currentId))
            {
                continue;
            }

            foreach (var nested in await groupStore.GetMemberGroupIdsAsync(currentId).ConfigureAwait(false))
            {
                stack.Push(nested);
            }
        }

        return false;
    }
}
