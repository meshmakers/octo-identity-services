using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Handler of <c>System.Identity/User.Merge-1</c> (AB#7778): a user administrator merges a duplicate user (the source,
///     named by <c>sourceUserName</c>) into the target user. Same result as REST <c>POST {tenant}/v1/users/{userName}/merge</c>.
/// </summary>
/// <remarks>
///     <para>
///         <b>One merge.</b> The method and REST share <see cref="IUserMergeService" />: the role change guard on the deletion
///         of the source user (AB#7914, <c>last-administrator</c>), the external logins of the source move to the target, the
///         sessions and refresh tokens of the source are revoked, the source user is deleted. Roles, groups, claims and
///         cross-tenant mappings of the source are not transferred (as in REST), so a merge never grants the target a role.
///     </para>
///     <para>
///         <b>Caller.</b> <see cref="IdentityAdminMethodHandlerBase{TParameters}" />: scope <c>octo_api</c> and role
///         <c>UserManagement</c> on the validated principal, <c>METHOD_FORBIDDEN</c> / <c>role-required</c> before the target is
///         read; a forged bus caller is rejected by the host. The gateway checks <c>Write</c> on the target
///         (<c>dataAccess: Write</c>); the source user, which the merge deletes, is checked here with the engine's data
///         permission evaluator (AB#7035): not readable = <c>SOURCE_USER_NOT_FOUND</c>, readable but not writable =
///         <c>METHOD_FORBIDDEN</c> / <c>data-permission</c>.
///     </para>
///     <para>
///         <b>Declared errors.</b> <c>SOURCE_USER_NOT_FOUND</c>, <c>CANNOT_MERGE_INTO_ITSELF</c>, <c>MERGE_FAILED</c> (parameter
///         <c>step</c> = <c>removeLogin</c>, <c>addLogin</c> or <c>deleteSource</c>, <c>loginProvider</c> for the login steps;
///         details = the error codes of the user manager). A missing <c>sourceUserName</c> is <c>METHOD_VALIDATION_FAILED</c>.
///     </para>
///     <para>
///         <b>Audit.</b> One <c>Identity.Method</c> event per call with the details <c>sourceUserName</c>, <c>sourceRtId</c>
///         (once found), <c>transferredLogins</c> and <c>revokedTokens</c> (success and <c>MERGE_FAILED</c>), and <c>reason</c>
///         for a refusal. Identifiers and counts only, never a token.
///     </para>
/// </remarks>
internal sealed class UserMergeHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<UserMergeParameters>(services)
{
    /// <summary>Declared error: the source user does not exist (or the caller cannot read it).</summary>
    internal const string SourceUserNotFound = "SOURCE_USER_NOT_FOUND";

    /// <summary>Declared error: source and target are the same user.</summary>
    internal const string CannotMergeIntoItself = "CANNOT_MERGE_INTO_ITSELF";

    /// <summary>Declared error: a login could not be moved or the source user could not be deleted.</summary>
    internal const string MergeFailed = "MERGE_FAILED";

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        UserMergeParameters parameters, CancellationToken cancellationToken)
    {
        var userManager = call.Services.GetRequiredService<UserManager<RtUser>>();
        var target = await userManager.FindByIdAsync(targetRtId.ToString()).ConfigureAwait(false);
        if (target == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var sourceUserName = parameters.SourceUserName?.Trim();
        if (string.IsNullOrEmpty(sourceUserName))
        {
            return CkMethodOutcome.ValidationFailed("sourceUserName", "required");
        }

        call.Details["sourceUserName"] = sourceUserName;
        var source = await userManager.FindByNameAsync(sourceUserName).ConfigureAwait(false);
        if (source == null)
        {
            return CkMethodOutcome.Fail(SourceUserNotFound);
        }

        call.Details["sourceRtId"] = source.RtId.ToString();
        if (source.RtId == target.RtId)
        {
            return CkMethodOutcome.Fail(CannotMergeIntoItself);
        }

        // The merge deletes the source user: the caller needs write access to it, not only to the target (AB#7035).
        var sourceEntity = new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtUser>(), source.RtId);
        var read = await call.EvaluateAsync(sourceEntity, RtDataAction.Read, cancellationToken).ConfigureAwait(false);
        if (!read.IsAllowed)
        {
            return CkMethodOutcome.Fail(SourceUserNotFound);
        }

        var write = await call.EvaluateAsync(sourceEntity, RtDataAction.Write, cancellationToken).ConfigureAwait(false);
        if (!write.IsAllowed)
        {
            return call.NotPermitted();
        }

        var result = await call.Services.GetRequiredService<IUserMergeService>()
            .MergeAsync(target, source, call.Caller, await ActorAsync(userManager, call).ConfigureAwait(false),
                cancellationToken)
            .ConfigureAwait(false);
        if (result.Status is UserMergeStatus.Merged or UserMergeStatus.LoginRemoveFailed or
            UserMergeStatus.LoginAddFailed or UserMergeStatus.SourceDeleteFailed)
        {
            call.Details["transferredLogins"] = result.TransferredLogins.ToString(System.Globalization.CultureInfo.InvariantCulture);
            call.Details["revokedTokens"] = result.RevokedTokens.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return result.Status switch
        {
            UserMergeStatus.Merged => CkMethodOutcome.Ok(),
            UserMergeStatus.SameUser => CkMethodOutcome.Fail(CannotMergeIntoItself),
            UserMergeStatus.RoleChangeRefused => call.Refuse(result.Refusal!),
            UserMergeStatus.LoginRemoveFailed => Failed("removeLogin", result),
            UserMergeStatus.LoginAddFailed => Failed("addLogin", result),
            _ => Failed("deleteSource", result)
        };
    }

    private static CkMethodOutcome Failed(string step, UserMergeResult result)
    {
        var parameters = new Dictionary<string, string> { ["step"] = step };
        if (result.LoginProvider != null)
        {
            parameters["loginProvider"] = result.LoginProvider;
        }

        return CkMethodOutcome.Fail(new CkMethodFailure(MergeFailed, parameters,
            result.Errors.Where(e => !string.IsNullOrWhiteSpace(e.Code))
                .Select(e => new CkMethodErrorDetail { Code = e.Code }).ToList()));
    }

    /// <summary>The caller for the log line of the session revocation: user name, else the client.</summary>
    private static async Task<AuditActor> ActorAsync(UserManager<RtUser> userManager, IdentityMethodCall call)
    {
        var principal = call.Principal;
        string? userName = null;
        if (principal.SubjectId != null)
        {
            var caller = await userManager.FindByIdAsync(principal.SubjectId).ConfigureAwait(false);
            userName = caller?.UserName;
        }

        return new AuditActor(principal.SubjectId, userName, principal.ClientId, principal.TenantId);
    }
}
