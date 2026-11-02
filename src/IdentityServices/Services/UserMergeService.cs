using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>Outcome of <see cref="IUserMergeService.MergeAsync" />.</summary>
public enum UserMergeStatus
{
    /// <summary>The logins were moved, the sessions of the source user revoked and the source user deleted.</summary>
    Merged,

    /// <summary>Source and target are the same user; nothing was changed.</summary>
    SameUser,

    /// <summary>The role change guard refused the deletion of the source user (e.g. the last user administrator); nothing was changed.</summary>
    RoleChangeRefused,

    /// <summary>A login could not be removed from the source user.</summary>
    LoginRemoveFailed,

    /// <summary>A login could not be added to the target user.</summary>
    LoginAddFailed,

    /// <summary>The source user could not be deleted after its logins were moved.</summary>
    SourceDeleteFailed
}

/// <summary>Result of a merge of two users.</summary>
/// <param name="Status">What happened.</param>
/// <param name="Refusal">The decision of the role change guard when <see cref="UserMergeStatus.RoleChangeRefused" />.</param>
/// <param name="LoginProvider">The login provider of the login that failed to move, for the login failures.</param>
/// <param name="Errors">The errors of the user manager for the failures; empty otherwise.</param>
/// <param name="TransferredLogins">Number of external logins that were moved to the target user.</param>
/// <param name="RevokedTokens">Number of tokens of the source user that were revoked.</param>
public sealed record UserMergeResult(
    UserMergeStatus Status,
    RoleChangeDecision? Refusal,
    string? LoginProvider,
    IReadOnlyList<IdentityError> Errors,
    int TransferredLogins,
    long RevokedTokens)
{
    internal static UserMergeResult Of(UserMergeStatus status) => new(status, null, null, [], 0, 0);
}

/// <summary>
///     The one way the identity service merges a duplicate user into another (AB#7778). Shared by the REST endpoint
///     <c>POST {tenant}/v1/users/{userName}/merge</c> and the CK method <c>System.Identity/User.Merge-1</c>, so both leave the
///     same state behind.
/// </summary>
/// <remarks>
///     <para>
///         <b>What moves.</b> The external logins (<c>UserLogins</c>) of the source user move to the target user, then the
///         source user is deleted. Nothing else moves: roles, group memberships, claims and cross-tenant mappings of the
///         source user are <b>not</b> transferred, they go away with the source user. So a merge never gives the target user
///         a role it did not have, and the guard only has to protect the deletion.
///     </para>
///     <para>
///         <b>Guard.</b> Before the first write the role change guard (AB#7914) evaluates the deletion of the source user:
///         the merge must not remove the last user that holds <c>UserManagement</c>.
///     </para>
///     <para>
///         <b>Sessions.</b> Before the source user is deleted, every refresh token, authorization and browser session of the
///         source user in this tenant is revoked (<see cref="IUserSessionRevocationService" />), so a token issued to the
///         duplicate account stops working at once.
///     </para>
///     <para>
///         <b>Order.</b> Each login is removed from the source user before it is added to the target user:
///         <c>UserManager.AddLoginAsync</c> refuses a login that another user still owns (<c>LoginAlreadyAssociated</c>).
///     </para>
/// </remarks>
public interface IUserMergeService
{
    /// <summary>Merges <paramref name="source" /> into <paramref name="target" />.</summary>
    /// <param name="target">The user that is kept and receives the logins.</param>
    /// <param name="source">The user whose logins move and that is deleted.</param>
    /// <param name="caller">The caller, for the role change guard.</param>
    /// <param name="actor">The caller, for the log line of the session revocation.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task<UserMergeResult> MergeAsync(RtUser target, RtUser source, RoleChangeCaller caller, AuditActor actor,
        CancellationToken cancellationToken = default);
}

internal sealed class UserMergeService(
    UserManager<RtUser> userManager,
    IUserStore<RtUser> userStore,
    IRoleChangeGuard roleChangeGuard,
    IUserSessionRevocationService sessionRevocationService,
    ILogger<UserMergeService> logger) : IUserMergeService
{
    public async Task<UserMergeResult> MergeAsync(RtUser target, RtUser source, RoleChangeCaller caller,
        AuditActor actor, CancellationToken cancellationToken = default)
    {
        if (target.RtId == source.RtId)
        {
            return UserMergeResult.Of(UserMergeStatus.SameUser);
        }

        // The source user is deleted at the end; that must not remove the last user administrator (AB#7914).
        var octoUserStore = userStore as OctoUserStore ??
                            throw new InvalidOperationException("The user store of the identity service is not the OctoUserStore.");
        var directRoles = (await octoUserStore.GetDirectRolesAsync(source).ConfigureAwait(false)).ToList();
        var decision = await roleChangeGuard
            .EvaluateAsync(new RoleChangeRequest(caller, source, directRoles, null), cancellationToken)
            .ConfigureAwait(false);
        if (!decision.IsAllowed)
        {
            return UserMergeResult.Of(UserMergeStatus.RoleChangeRefused) with { Refusal = decision };
        }

        var sourceLogins = await userManager.GetLoginsAsync(source).ConfigureAwait(false);
        var transferred = 0;
        foreach (var login in sourceLogins)
        {
            var removeResult = await userManager.RemoveLoginAsync(source, login.LoginProvider, login.ProviderKey)
                .ConfigureAwait(false);
            if (!removeResult.Succeeded)
            {
                LogIdentityError("Remove login from source during merge", removeResult.Errors);
                return new UserMergeResult(UserMergeStatus.LoginRemoveFailed, null, login.LoginProvider,
                    removeResult.Errors.ToList(), transferred, 0);
            }

            var addResult = await userManager.AddLoginAsync(target, login).ConfigureAwait(false);
            if (!addResult.Succeeded)
            {
                LogIdentityError("Add login during merge", addResult.Errors);
                return new UserMergeResult(UserMergeStatus.LoginAddFailed, null, login.LoginProvider,
                    addResult.Errors.ToList(), transferred, 0);
            }

            transferred++;
        }

        // Tokens issued to the duplicate account must stop working (refresh tokens, authorizations, browser sessions).
        var revocation = await sessionRevocationService.RevokeAsync(source, actor, cancellationToken)
            .ConfigureAwait(false);

        var deleteResult = await userManager.DeleteAsync(source).ConfigureAwait(false);
        if (!deleteResult.Succeeded)
        {
            LogIdentityError("Delete source user during merge", deleteResult.Errors);
            return new UserMergeResult(UserMergeStatus.SourceDeleteFailed, null, null, deleteResult.Errors.ToList(),
                transferred, revocation.RevokedTokens);
        }

        logger.LogInformation(
            "Successfully merged user '{SourceUser}' into '{TargetUser}'. Transferred {LoginCount} external login(s), " +
            "revoked {RevokedTokens} token(s) of the source user",
            source.UserName, target.UserName, transferred, revocation.RevokedTokens);
        return new UserMergeResult(UserMergeStatus.Merged, null, null, [], transferred, revocation.RevokedTokens);
    }

    private void LogIdentityError(string operation, IEnumerable<IdentityError> errors)
    {
        var identityErrors = errors as IdentityError[] ?? errors.ToArray();
        logger.LogError("{Operation} failed with errors: '{Errors}' and codes '{Codes}'",
            operation,
            string.Join(", ", identityErrors.Select(x => x.Description)),
            string.Join(", ", identityErrors.Select(x => x.Code)));
    }
}
