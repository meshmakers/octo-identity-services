using IdentityServerPersistence.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using OpenIddictAbstractions = global::OpenIddict.Abstractions;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Ends every session and token of a user in the current tenant (AB#7899): rotates the security stamp, revokes all
///     OAuth tokens and authorizations of the subject and removes its server-side browser sessions.
/// </summary>
/// <remarks>
///     Issued JWT access tokens are not stored and cannot be revoked; they stay valid until they expire. Refresh tokens
///     and browser sessions stop working at once. Everything is tenant-scoped: the same person's identities in other
///     tenants are not touched.
/// </remarks>
public interface IUserSessionRevocationService
{
    /// <summary>Revokes everything of <paramref name="user" />; one audit log line names the acting user.</summary>
    Task<UserSessionRevocationResultDto> RevokeAsync(RtUser user, string? actingUser,
        CancellationToken cancellationToken = default);

    /// <summary>
    ///     The same for every cross-tenant shadow user (<c>xt_…</c>) of the tenant; with <paramref name="dryRun" /> only
    ///     the counts. Dry run and apply use the same selection — every token and authorization that is not revoked yet,
    ///     and the browser sessions — so the dry run reports exactly what the apply revokes (AB#7957).
    /// </summary>
    Task<ShadowUserSessionRevocationResultDto> RevokeShadowUsersAsync(bool dryRun, string? actingUser,
        CancellationToken cancellationToken = default);
}

/// <inheritdoc />
internal sealed class UserSessionRevocationService(
    UserManager<RtUser> userManager,
    OpenIddictAbstractions.IOpenIddictTokenStore<RtOAuthToken> tokenStore,
    OpenIddictAbstractions.IOpenIddictAuthorizationStore<RtOAuthAuthorization> authorizationStore,
    IMultiTenancyResolverService multiTenancyResolverService,
    ILogger<UserSessionRevocationService> logger) : IUserSessionRevocationService
{
    /// <summary>Upper bound of the user names listed in a bulk result.</summary>
    internal const int MaxListedUserNames = 100;

    public async Task<UserSessionRevocationResultDto> RevokeAsync(RtUser user, string? actingUser,
        CancellationToken cancellationToken = default)
    {
        var result = await RevokeCoreAsync(user, cancellationToken);
        logger.LogInformation(
            "Sessions revoked: tenant '{TenantId}', subject '{Subject}', user '{UserName}', acting user '{ActingUser}'; " +
            "revoked {RevokedTokens} token(s), {RevokedAuthorizations} authorization(s), removed {RemovedSessions} session(s)",
            multiTenancyResolverService.GetTenantId(), result.Subject, result.UserName, actingUser ?? "(unknown)",
            result.RevokedTokens, result.RevokedAuthorizations, result.RemovedSessions);
        return result;
    }

    public async Task<ShadowUserSessionRevocationResultDto> RevokeShadowUsersAsync(bool dryRun, string? actingUser,
        CancellationToken cancellationToken = default)
    {
        var shadowUsers = await FindShadowUsersAsync();
        long tokens = 0, authorizations = 0, sessions = 0;
        foreach (var user in shadowUsers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Dry run and apply share one selection (AB#7957): the dry run reports exactly what the apply revokes.
            var selection = await SelectAsync(user, cancellationToken);
            if (!dryRun)
            {
                await RevokeSelectionAsync(user, selection, cancellationToken);
            }

            tokens += selection.Tokens.Count;
            authorizations += selection.Authorizations.Count;
            sessions += selection.Sessions;
        }

        var tenantId = multiTenancyResolverService.GetTenantId();
        logger.LogInformation(
            "Shadow-user sessions {Mode}: tenant '{TenantId}', acting user '{ActingUser}'; {Users} user(s), " +
            "{Tokens} token(s), {Authorizations} authorization(s), {Sessions} session(s)",
            dryRun ? "counted (dry run)" : "revoked", tenantId, actingUser ?? "(unknown)", shadowUsers.Count, tokens,
            authorizations, sessions);

        return new ShadowUserSessionRevocationResultDto
        {
            DryRun = dryRun,
            Scope = "shadowUsers",
            TenantId = tenantId,
            Users = shadowUsers.Count,
            Tokens = tokens,
            Authorizations = authorizations,
            Sessions = sessions,
            UserNames = shadowUsers.Select(u => u.UserName ?? string.Empty)
                .Take(MaxListedUserNames).ToList()
        };
    }

    private async Task<UserSessionRevocationResultDto> RevokeCoreAsync(RtUser user, CancellationToken cancellationToken)
    {
        var selection = await SelectAsync(user, cancellationToken);
        await RevokeSelectionAsync(user, selection, cancellationToken);

        return new UserSessionRevocationResultDto
        {
            UserName = user.UserName ?? string.Empty,
            Subject = selection.Subject,
            SecurityStampRotated = true,
            RevokedTokens = selection.Tokens.Count,
            RevokedAuthorizations = selection.Authorizations.Count,
            RemovedSessions = selection.Sessions
        };
    }

    /// <summary>
    ///     The one selection both the dry run and the apply use (AB#7957): every token and authorization of the subject
    ///     that is not revoked yet (valid, redeemed, inactive, …) and its server-side browser sessions.
    /// </summary>
    private async Task<RevocationSelection> SelectAsync(RtUser user, CancellationToken cancellationToken)
    {
        var subject = user.RtId.ToString();
        var tokens = new List<RtOAuthToken>();
        await foreach (var token in tokenStore.FindBySubjectAsync(subject, cancellationToken))
        {
            if (IsRevocable(token.Status))
            {
                tokens.Add(token);
            }
        }

        var authorizations = new List<RtOAuthAuthorization>();
        await foreach (var authorization in authorizationStore.FindBySubjectAsync(subject, cancellationToken))
        {
            if (IsRevocable(authorization.Status))
            {
                authorizations.Add(authorization);
            }
        }

        return new RevocationSelection(subject, tokens, authorizations, await CountSessionsAsync(subject));
    }

    /// <summary>Not revoked yet — already revoked entries are neither counted nor revoked again.</summary>
    private static bool IsRevocable(string? status)
        => !string.Equals(status, OpenIddictAbstractions.OpenIddictConstants.Statuses.Revoked, StringComparison.Ordinal);

    private async Task RevokeSelectionAsync(RtUser user, RevocationSelection selection,
        CancellationToken cancellationToken)
    {
        var stamp = await userManager.UpdateSecurityStampAsync(user);
        if (!stamp.Succeeded)
        {
            throw new InvalidOperationException($"Security stamp of user '{selection.Subject}' could not be rotated.");
        }

        foreach (var token in selection.Tokens)
        {
            await tokenStore.SetStatusAsync(token, OpenIddictAbstractions.OpenIddictConstants.Statuses.Revoked,
                cancellationToken);
            await tokenStore.UpdateAsync(token, cancellationToken);
        }

        foreach (var authorization in selection.Authorizations)
        {
            await authorizationStore.SetStatusAsync(authorization,
                OpenIddictAbstractions.OpenIddictConstants.Statuses.Revoked, cancellationToken);
            await authorizationStore.UpdateAsync(authorization, cancellationToken);
        }

        if (selection.Sessions > 0)
        {
            await RemoveSessionsAsync(selection.Subject);
        }
    }

    private async Task<List<RtUser>> FindShadowUsersAsync()
    {
        var repository = multiTenancyResolverService.GetTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return result.Items.Where(u => CrossTenantShadowUserName.IsShadowUserName(u.UserName)).ToList();
    }

    private async Task<long> CountSessionsAsync(string subject)
    {
        var repository = multiTenancyResolverService.GetTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session,
            RtEntityQueryOptions.Create().FieldEquals(nameof(RtServerSideSession.SubjectId), subject));
        await session.CommitTransactionAsync();
        return result.Items.LongCount();
    }

    private async Task RemoveSessionsAsync(string subject)
    {
        var repository = multiTenancyResolverService.GetTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.DeleteManyRtEntitiesAsync<RtServerSideSession>(session,
            FieldFilterCriteria.Create(LogicalOperators.And).FieldEquals(nameof(RtServerSideSession.SubjectId), subject),
            DeleteOptions.Erase);
        await session.CommitTransactionAsync();
    }
}

/// <summary>What a revocation of one subject touches; shared by the dry run and the apply (AB#7957).</summary>
internal sealed record RevocationSelection(
    string Subject,
    IReadOnlyList<RtOAuthToken> Tokens,
    IReadOnlyList<RtOAuthAuthorization> Authorizations,
    long Sessions);
