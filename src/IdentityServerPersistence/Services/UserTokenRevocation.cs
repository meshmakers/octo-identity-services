using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Revokes every OAuth token (refresh tokens included) and every authorization of one subject in the current tenant.
/// </summary>
/// <remarks>
///     Idempotent: tokens that are already revoked stay revoked, so calling it twice around a write is safe. The stores
///     are tenant-scoped; other tenants are never touched.
/// </remarks>
public interface IUserTokenRevocation
{
    /// <summary>Revokes all tokens and authorizations of <paramref name="subject" /> in the current tenant.</summary>
    /// <param name="subject">The subject (user <c>RtId</c>).</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The number of revoked tokens and authorizations.</returns>
    Task<(long Tokens, long Authorizations)> RevokeAllAsync(string subject, CancellationToken cancellationToken);
}

/// <inheritdoc />
public sealed class UserTokenRevocation(
    IOpenIddictTokenStore<RtOAuthToken> tokenStore,
    IOpenIddictAuthorizationStore<RtOAuthAuthorization> authorizationStore) : IUserTokenRevocation
{
    /// <inheritdoc />
    public async Task<(long Tokens, long Authorizations)> RevokeAllAsync(string subject,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var tokens = await tokenStore.RevokeBySubjectAsync(subject, cancellationToken).ConfigureAwait(false);
        var authorizations = await authorizationStore.RevokeBySubjectAsync(subject, cancellationToken)
            .ConfigureAwait(false);
        return (tokens, authorizations);
    }
}
