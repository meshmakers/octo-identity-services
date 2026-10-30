using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Dtos;
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
    ///     the counts.
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
    private const string ValidStatus = "valid";

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
            if (dryRun)
            {
                var subject = user.RtId.ToString();
                tokens += await CountValidAsync(tokenStore.FindBySubjectAsync(subject, cancellationToken),
                    t => t.Status);
                authorizations += await CountValidAsync(
                    authorizationStore.FindBySubjectAsync(subject, cancellationToken), a => a.Status);
                sessions += await CountSessionsAsync(subject);
            }
            else
            {
                var result = await RevokeCoreAsync(user, cancellationToken);
                tokens += result.RevokedTokens;
                authorizations += result.RevokedAuthorizations;
                sessions += result.RemovedSessions;
            }
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
                .Take(ShadowUserSessionRevocationResultDto.MaxListedUserNames).ToList()
        };
    }

    private async Task<UserSessionRevocationResultDto> RevokeCoreAsync(RtUser user, CancellationToken cancellationToken)
    {
        var subject = user.RtId.ToString();
        var stamp = await userManager.UpdateSecurityStampAsync(user);
        if (!stamp.Succeeded)
        {
            throw new InvalidOperationException($"Security stamp of user '{subject}' could not be rotated.");
        }

        var tokens = await tokenStore.RevokeBySubjectAsync(subject, cancellationToken);
        var authorizations = await authorizationStore.RevokeBySubjectAsync(subject, cancellationToken);
        var sessions = await RemoveSessionsAsync(subject);

        return new UserSessionRevocationResultDto
        {
            UserName = user.UserName ?? string.Empty,
            Subject = subject,
            SecurityStampRotated = true,
            RevokedTokens = tokens,
            RevokedAuthorizations = authorizations,
            RemovedSessions = sessions
        };
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

    private async Task<long> RemoveSessionsAsync(string subject)
    {
        var count = await CountSessionsAsync(subject);
        if (count == 0)
        {
            return 0;
        }

        var repository = multiTenancyResolverService.GetTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.DeleteManyRtEntitiesAsync<RtServerSideSession>(session,
            FieldFilterCriteria.Create(LogicalOperators.And).FieldEquals(nameof(RtServerSideSession.SubjectId), subject),
            DeleteOptions.Erase);
        await session.CommitTransactionAsync();
        return count;
    }

    private static async Task<long> CountValidAsync<T>(IAsyncEnumerable<T> items, Func<T, string?> status)
    {
        long count = 0;
        await foreach (var item in items)
        {
            if (string.Equals(status(item), ValidStatus, StringComparison.Ordinal))
            {
                count++;
            }
        }

        return count;
    }
}
