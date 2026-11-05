using IdentityServerPersistence.Services;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

internal sealed class UserCredentialChangeService(
    UserManager<RtUser> userManager,
    IUserTokenRevocation tokenRevocation,
    IMultiTenancyResolverService multiTenancyResolverService,
    ILogger<UserCredentialChangeService> logger) : IUserCredentialChangeService
{
    public async Task OnPasswordChangedAsync(RtUser user, PasswordChangePath path, string? actingUser,
        CancellationToken cancellationToken = default)
    {
        var (subject, tokens, authorizations) = await RevokeAsync(user, "a password change", cancellationToken);

        // Audit entry: identifiers only, never a password, hash or token value.
        logger.LogInformation(
            "Password changed: tenant '{TenantId}', subject '{Subject}', acting user '{ActingUser}', path '{Path}'; " +
            "revoked {RevokedTokens} token(s) and {RevokedAuthorizations} authorization(s)",
            multiTenancyResolverService.GetTenantId(), subject, actingUser ?? "(anonymous reset token)", path,
            tokens, authorizations);
    }

    public async Task OnSecondFactorDisabledAsync(RtUser user, TwoFactorDisablePath path, string? actingUser,
        bool twoFactorWasEnabled, CancellationToken cancellationToken = default)
    {
        var (subject, tokens, authorizations) =
            await RevokeAsync(user, "switching the second factor off", cancellationToken);

        // Audit entry: identifiers only, never a key, recovery code or token value.
        logger.LogInformation(
            "Second factor switched off by an administrator: tenant '{TenantId}', subject '{Subject}', acting user " +
            "'{ActingUser}', path '{Path}', two-factor was enabled: {TwoFactorWasEnabled}; revoked {RevokedTokens} " +
            "token(s) and {RevokedAuthorizations} authorization(s)",
            multiTenancyResolverService.GetTenantId(), subject, actingUser ?? "(unknown)", path, twoFactorWasEnabled,
            tokens, authorizations);
    }

    private async Task<(string Subject, long Tokens, long Authorizations)> RevokeAsync(RtUser user, string cause,
        CancellationToken cancellationToken)
    {
        var subject = user.RtId.ToString();

        // Redeeming a refresh token checks only CanSignIn, never the security stamp, so the tokens
        // must be revoked explicitly. Stores are tenant-scoped: other tenants are not touched.
        var stampResult = await userManager.UpdateSecurityStampAsync(user);
        if (!stampResult.Succeeded)
        {
            throw new InvalidOperationException(
                $"Security stamp of user '{subject}' could not be updated after {cause}.");
        }

        // AB#8018: for a password change this is the second revocation; OctoUserManager revoked once before the
        // password was stored, so a crash between the password write and this call leaves no old token valid.
        var (tokens, authorizations) = await tokenRevocation.RevokeAllAsync(subject, cancellationToken);
        return (subject, tokens, authorizations);
    }
}
