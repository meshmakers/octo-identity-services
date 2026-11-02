using IdentityServerPersistence;
using IdentityServerPersistence.Services.ScratchTenants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the group methods (declared in <c>ck-group.yaml</c>).</summary>
internal static class GroupMethodErrors
{
    public const string MemberNotFound = "MEMBER_NOT_FOUND";
    public const string MemberAlreadyInGroup = "MEMBER_ALREADY_IN_GROUP";
    public const string MemberNotInGroup = "MEMBER_NOT_IN_GROUP";
}

/// <summary>
///     Shared flow of <c>Group.AddMember</c> and <c>Group.RemoveMember</c> (AB#7779): the same rules as the REST endpoints
///     <c>PUT/DELETE system/v1/groups/{group}/members/users/{user}</c> and <c>.../members/clients/{client}</c> of
///     <c>GroupsController</c>, never more.
/// </summary>
/// <remarks>
///     <para>
///         <b>Parity with REST.</b> REST lets a caller change group members when the token carries scope <c>octo_api</c> and the
///         role <c>UserManagement</c>, and the group exists. Adding or removing a <em>user</em> runs the role change guard
///         (<see cref="RoleGraphChange.MemberAdded" />, <see cref="RoleGraphChange.MemberRemoved" />, AB#7927): no self-grant,
///         no built-in role the caller does not hold, the last user administrator stays. Removing a <em>client</em> runs no guard
///         (a client gives nothing to anybody and does not count as an administrator); adding a client does, because the
///         client then inherits the roles of the group. Removing a client records the revocation of a scratch tenant's creator
///         mirror, so the tenant setup does not grant it again (AB#7192), exactly like REST.
///     </para>
///     <para>
///         <b>Typed answers where REST is silent or fails.</b> REST ends in an unhandled engine error for a member that does
///         not exist and is silent about duplicates; the methods answer <c>MEMBER_NOT_FOUND</c> for a member that does not
///         exist (or that the caller cannot read, AB#7035), <c>MEMBER_ALREADY_IN_GROUP</c> and <c>MEMBER_NOT_IN_GROUP</c>.
///         The member of kind <c>Client</c> is the rtId of the client (as in the REST route); the OAuth client id is accepted too.
///     </para>
///     <para>
///         <b>Audit.</b> One <c>Identity.Method</c> event per call with <c>memberKind</c>, <c>memberId</c> and, for a refusal
///         of the guard, <c>reason</c> (and <c>roleNames</c>). Nothing is revoked: a membership change shows in the next token.
///     </para>
/// </remarks>
internal abstract class GroupMemberMethodHandlerBase<TParameters>(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<TParameters>(services) where TParameters : class
{
    /// <summary>The kind of member the call is about, as the model declares it.</summary>
    protected abstract RtGroupMemberKindEnum Kind(TParameters parameters);

    /// <summary>The member id parameter.</summary>
    protected abstract string? MemberId(TParameters parameters);

    /// <summary>Applies the change; the member was resolved, the group exists.</summary>
    protected abstract Task<CkMethodOutcome> ApplyMemberAsync(IdentityMethodCall call, RtGroup group,
        GroupMemberKind kind, ResolvedMember member, bool isMember, CancellationToken cancellationToken);

    protected sealed override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        TParameters parameters, CancellationToken cancellationToken)
    {
        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        var group = await groupStore.FindByIdAsync(targetRtId).ConfigureAwait(false);
        if (group == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var memberKind = Kind(parameters);
        var kind = memberKind == RtGroupMemberKindEnum.Client ? GroupMemberKind.Client : GroupMemberKind.User;
        var memberId = MemberId(parameters)?.Trim();
        call.Details["memberKind"] = memberKind.ToString();
        call.Details["memberId"] = memberId ?? string.Empty;
        if (string.IsNullOrEmpty(memberId))
        {
            return MemberNotFound();
        }

        var member = await ResolveAsync(call, kind, memberId).ConfigureAwait(false);
        var memberIds = kind == GroupMemberKind.User
            ? await groupStore.GetMemberUserIdsAsync(group.RtId).ConfigureAwait(false)
            : await groupStore.GetMemberClientIdsAsync(group.RtId).ConfigureAwait(false);
        var isMember = memberIds.Contains(member.RtId, StringComparer.OrdinalIgnoreCase);

        if (member.Exists)
        {
            var verdict = await call.EvaluateAsync(member.Entity, RtDataAction.Read, cancellationToken)
                .ConfigureAwait(false);
            if (!verdict.IsAllowed)
            {
                return MemberNotFound();
            }
        }

        return await ApplyMemberAsync(call, group, kind, member, isMember, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Runs the role change guard on a change of the group graph; <c>null</c> when it is allowed.</summary>
    protected static async Task<CkMethodOutcome?> GuardAsync(IdentityMethodCall call, RoleGraphChange change,
        CancellationToken cancellationToken)
    {
        var decision = await call.Services.GetRequiredService<IRoleChangeGuard>()
            .EvaluateAsync(call.Caller, change, cancellationToken).ConfigureAwait(false);
        return decision.IsAllowed ? null : call.Refuse(decision);
    }

    protected static CkMethodOutcome MemberNotFound() => CkMethodOutcome.Fail(GroupMethodErrors.MemberNotFound);

    private static async Task<ResolvedMember> ResolveAsync(IdentityMethodCall call, GroupMemberKind kind, string memberId)
    {
        var type = kind == GroupMemberKind.User
            ? RtEntityExtensions.GetRtCkTypeId<RtUser>()
            : RtEntityExtensions.GetRtCkTypeId<RtClient>();
        if (kind == GroupMemberKind.Client && !OctoObjectId.TryParse(memberId, out _))
        {
            // The OAuth client id of the client instead of its rtId.
            var client = await call.Services.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(memberId)
                .ConfigureAwait(false);
            return client == null
                ? ResolvedMember.Missing(type, memberId)
                : new ResolvedMember(client.RtId.ToString(), new RtEntityId(type, client.RtId), true);
        }

        if (!OctoObjectId.TryParse(memberId, out var rtId))
        {
            return ResolvedMember.Missing(type, memberId);
        }

        var exists = kind == GroupMemberKind.User
            ? await call.Services.GetRequiredService<UserManager<RtUser>>().FindByIdAsync(rtId.ToString())
                .ConfigureAwait(false) != null
            : await ClientExistsAsync(call, rtId).ConfigureAwait(false);
        return new ResolvedMember(rtId.ToString(), new RtEntityId(type, rtId), exists);
    }

    private static async Task<bool> ClientExistsAsync(IdentityMethodCall call, OctoObjectId rtId)
    {
        var repository = call.Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        using var session = await repository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();
        var client = await repository.GetRtEntityByRtIdAsync<RtClient>(session, rtId).ConfigureAwait(false);
        await session.CommitTransactionAsync().ConfigureAwait(false);
        return client != null;
    }
}

/// <summary>A member of a group call: its rtId (normalized), the entity id for the data-permission check, and whether it exists.</summary>
internal sealed record ResolvedMember(string RtId, RtEntityId Entity, bool Exists)
{
    public static ResolvedMember Missing(RtCkId<CkTypeId> type, string raw) =>
        new(raw, new RtEntityId(type, OctoObjectId.TryParse(raw, out var id) ? id : OctoObjectId.Empty), false);
}

/// <summary>
///     Handler of <c>System.Identity/Group.AddMember-1</c> (AB#7779): adds a user or a client to a group, with the rules of
///     <c>PUT system/v1/groups/{group}/members/users|clients/{id}</c> (see <see cref="GroupMemberMethodHandlerBase{T}" />).
/// </summary>
internal sealed class GroupAddMemberHandler(IServiceProvider services)
    : GroupMemberMethodHandlerBase<GroupAddMemberParameters>(services)
{
    protected override RtGroupMemberKindEnum Kind(GroupAddMemberParameters parameters) => parameters.MemberKind;

    protected override string? MemberId(GroupAddMemberParameters parameters) => parameters.MemberId;

    protected override async Task<CkMethodOutcome> ApplyMemberAsync(IdentityMethodCall call, RtGroup group,
        GroupMemberKind kind, ResolvedMember member, bool isMember, CancellationToken cancellationToken)
    {
        if (!member.Exists)
        {
            return MemberNotFound();
        }

        if (isMember)
        {
            return CkMethodOutcome.Fail(GroupMethodErrors.MemberAlreadyInGroup);
        }

        var refusal = await GuardAsync(call, new RoleGraphChange.MemberAdded(group.RtId.ToString(), kind, member.RtId),
            cancellationToken).ConfigureAwait(false);
        if (refusal != null)
        {
            return refusal;
        }

        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        if (kind == GroupMemberKind.User)
        {
            await groupStore.AddMemberUserAsync(group.RtId, member.RtId).ConfigureAwait(false);
        }
        else
        {
            await groupStore.AddMemberClientAsync(group.RtId, member.RtId).ConfigureAwait(false);
        }

        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/Group.RemoveMember-1</c> (AB#7779): removes a user or a client from a group, with the
///     rules of <c>DELETE system/v1/groups/{group}/members/users|clients/{id}</c> (see <see cref="GroupMemberMethodHandlerBase{T}" />).
/// </summary>
internal sealed class GroupRemoveMemberHandler(IServiceProvider services)
    : GroupMemberMethodHandlerBase<GroupRemoveMemberParameters>(services)
{
    protected override RtGroupMemberKindEnum Kind(GroupRemoveMemberParameters parameters) => parameters.MemberKind;

    protected override string? MemberId(GroupRemoveMemberParameters parameters) => parameters.MemberId;

    protected override async Task<CkMethodOutcome> ApplyMemberAsync(IdentityMethodCall call, RtGroup group,
        GroupMemberKind kind, ResolvedMember member, bool isMember, CancellationToken cancellationToken)
    {
        if (!isMember)
        {
            return member.Exists
                ? CkMethodOutcome.Fail(GroupMethodErrors.MemberNotInGroup)
                : MemberNotFound();
        }

        var groupStore = call.Services.GetRequiredService<IGroupStore>();
        if (kind == GroupMemberKind.User)
        {
            var refusal = await GuardAsync(call,
                new RoleGraphChange.MemberRemoved(group.RtId.ToString(), kind, member.RtId), cancellationToken)
                .ConfigureAwait(false);
            if (refusal != null)
            {
                return refusal;
            }

            await groupStore.RemoveMemberUserAsync(group.RtId, member.RtId).ConfigureAwait(false);
            return CkMethodOutcome.Ok();
        }

        // No guard for a client (REST: removing a client gives nothing to anybody). AB#7192: the revoke of a scratch tenant's
        // creator mirror is recorded BEFORE the membership goes, as in REST.
        if (OctoObjectId.TryParse(member.RtId, out var clientRtId))
        {
            await call.Services.GetRequiredService<IScratchTenantGrantService>().RecordRevocationAsync(
                call.Services.GetRequiredService<IMultiTenancyResolverService>().GetTenantId(), group.RtId,
                clientRtId, call.Principal.Subject ?? call.Principal.ClientId ?? "method").ConfigureAwait(false);
        }

        await groupStore.RemoveMemberClientAsync(group.RtId, member.RtId).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
