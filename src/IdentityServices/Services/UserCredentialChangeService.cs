using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using OpenIddictAbstractions = global::OpenIddict.Abstractions;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

internal sealed class UserCredentialChangeService(
    UserManager<RtUser> userManager,
    OpenIddictAbstractions.IOpenIddictTokenStore<RtOAuthToken> tokenStore,
    OpenIddictAbstractions.IOpenIddictAuthorizationStore<RtOAuthAuthorization> authorizationStore,
    IMultiTenancyResolverService multiTenancyResolverService,
    ILogger<UserCredentialChangeService> logger) : IUserCredentialChangeService
{
    public async Task OnPasswordChangedAsync(RtUser user, PasswordChangePath path, string? actingUser,
        CancellationToken cancellationToken = default)
    {
        var subject = user.RtId.ToString();

        // Redeeming a refresh token checks only CanSignIn, never the security stamp, so the tokens
        // must be revoked explicitly. Stores are tenant-scoped: other tenants are not touched.
        var stampResult = await userManager.UpdateSecurityStampAsync(user);
        if (!stampResult.Succeeded)
        {
            throw new InvalidOperationException(
                $"Security stamp of user '{subject}' could not be updated after a password change.");
        }

        var tokens = await tokenStore.RevokeBySubjectAsync(subject, cancellationToken);
        var authorizations = await authorizationStore.RevokeBySubjectAsync(subject, cancellationToken);

        // Audit entry: identifiers only, never a password, hash or token value.
        logger.LogInformation(
            "Password changed: tenant '{TenantId}', subject '{Subject}', acting user '{ActingUser}', path '{Path}'; " +
            "revoked {RevokedTokens} token(s) and {RevokedAuthorizations} authorization(s)",
            multiTenancyResolverService.GetTenantId(), subject, actingUser ?? "(anonymous reset token)", path,
            tokens, authorizations);
    }
}
