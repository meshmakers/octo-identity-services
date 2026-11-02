using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>Kind of second-factor code a user presents.</summary>
public enum SecondFactorCodeKind
{
    /// <summary>A TOTP code of the user's authenticator app.</summary>
    Authenticator,

    /// <summary>A code sent by e-mail (email token provider).</summary>
    Email,

    /// <summary>A single-use recovery code.</summary>
    RecoveryCode
}

/// <summary>Outcome of a cross-tenant second-factor verification.</summary>
public enum SecondFactorVerificationStatus
{
    /// <summary>The code is valid; the source user's failed-access count was reset.</summary>
    Verified,

    /// <summary>The code is wrong; it counted against the source user's lockout.</summary>
    Invalid,

    /// <summary>The source user is locked out (before or because of this attempt).</summary>
    LockedOut,

    /// <summary>The source user or tenant does not exist (any more), or 2FA is no longer enabled.</summary>
    Unavailable
}

/// <summary>Which second-factor methods the source user can use.</summary>
public sealed record SecondFactorOptions(bool CanUseAuthenticator, bool CanUseEmail);

/// <summary>
///     Verifies a second factor of a user who lives in ANOTHER tenant than the current request (AB#7804): the
///     cross-tenant password login on a child tenant must ask for the second factor of the source user, whose
///     authenticator key, recovery codes, security stamp and lockout counter live in the source tenant's database.
/// </summary>
public interface ICrossTenantSecondFactorVerifier
{
    /// <summary>The methods the source user can use; <c>null</c> when the user cannot be found.</summary>
    Task<SecondFactorOptions?> GetOptionsAsync(string sourceTenantId, string sourceUserId);

    /// <summary>
    ///     Verifies <paramref name="code" /> against the source user. A wrong code counts against the source user's
    ///     lockout, exactly like a wrong code of a local 2FA sign-in; a valid one resets the counter. A recovery
    ///     code is redeemed (single use) in the source tenant.
    /// </summary>
    Task<SecondFactorVerificationStatus> VerifyAsync(
        string sourceTenantId, string sourceUserId, SecondFactorCodeKind kind, string code);

    /// <summary>
    ///     Generates an e-mail code for the source user (mirrors the local <c>send-2fa-email</c>, whose delivery is
    ///     still a stub). Returns <c>false</c> when the user cannot be found or has no e-mail address.
    /// </summary>
    Task<bool> GenerateEmailCodeAsync(string sourceTenantId, string sourceUserId);
}

/// <summary>
///     <see cref="ICrossTenantSecondFactorVerifier" /> over a <see cref="UserManager{TUser}" /> bound to the source
///     tenant: the same <see cref="OctoUserStore" />, token providers, options and validators as the request-scoped
///     manager, but wired to the source tenant's repository instead of the request's. Using the framework manager
///     (not a hand-written TOTP check) keeps the cross-tenant verification identical to the local one —
///     authenticator time window, e-mail token provider, recovery-code redemption and lockout arithmetic.
/// </summary>
public sealed class CrossTenantSecondFactorVerifier(
    ITenantRegistry tenantRegistry,
    IGroupRoleResolver groupRoleResolver,
    IOptions<IdentityOptions> identityOptions,
    IPasswordHasher<RtUser> passwordHasher,
    IEnumerable<IUserValidator<RtUser>> userValidators,
    IEnumerable<IPasswordValidator<RtUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errorDescriber,
    IServiceProvider services,
    ILogger<UserManager<RtUser>> userManagerLogger,
    ILogger<CrossTenantSecondFactorVerifier> logger) : ICrossTenantSecondFactorVerifier
{
    public async Task<SecondFactorOptions?> GetOptionsAsync(string sourceTenantId, string sourceUserId)
    {
        using var manager = await CreateManagerAsync(sourceTenantId);
        var user = manager == null ? null : await manager.FindByIdAsync(sourceUserId);
        if (manager == null || user == null)
        {
            return null;
        }

        return new SecondFactorOptions(
            !string.IsNullOrEmpty(await manager.GetAuthenticatorKeyAsync(user)),
            await manager.IsEmailConfirmedAsync(user));
    }

    public async Task<SecondFactorVerificationStatus> VerifyAsync(
        string sourceTenantId, string sourceUserId, SecondFactorCodeKind kind, string code)
    {
        using var manager = await CreateManagerAsync(sourceTenantId);
        var user = manager == null ? null : await manager.FindByIdAsync(sourceUserId);
        if (manager == null || user == null || !await manager.GetTwoFactorEnabledAsync(user))
        {
            return SecondFactorVerificationStatus.Unavailable;
        }

        if (await manager.IsLockedOutAsync(user))
        {
            return SecondFactorVerificationStatus.LockedOut;
        }

        var verified = kind switch
        {
            SecondFactorCodeKind.Authenticator => await manager.VerifyTwoFactorTokenAsync(
                user, manager.Options.Tokens.AuthenticatorTokenProvider, code),
            SecondFactorCodeKind.Email => await manager.VerifyTwoFactorTokenAsync(
                user, TokenOptions.DefaultEmailProvider, code),
            SecondFactorCodeKind.RecoveryCode => (await manager.RedeemTwoFactorRecoveryCodeAsync(user, code)).Succeeded,
            _ => false
        };

        if (verified)
        {
            await manager.ResetAccessFailedCountAsync(user);
            return SecondFactorVerificationStatus.Verified;
        }

        // AB#7854: the failure is counted atomically on the stored source user (OctoUserManager). A failure to count
        // must not look like an ordinary wrong code that leaves the counter untouched.
        var counted = await manager.AccessFailedAsync(user);
        if (!counted.Succeeded)
        {
            logger.LogWarning(
                "Cross-tenant second factor: failed attempt of user '{UserId}' of tenant '{TenantId}' could not be counted",
                sourceUserId, sourceTenantId);
        }

        logger.LogInformation(
            "Cross-tenant second factor rejected for user '{UserId}' of tenant '{TenantId}' ({Kind})",
            sourceUserId, sourceTenantId, kind);
        return await manager.IsLockedOutAsync(user)
            ? SecondFactorVerificationStatus.LockedOut
            : SecondFactorVerificationStatus.Invalid;
    }

    public async Task<bool> GenerateEmailCodeAsync(string sourceTenantId, string sourceUserId)
    {
        using var manager = await CreateManagerAsync(sourceTenantId);
        var user = manager == null ? null : await manager.FindByIdAsync(sourceUserId);
        if (manager == null || user == null || string.IsNullOrEmpty(user.Email))
        {
            return false;
        }

        // Same as the local send-2fa-email: the code is generated, delivery is not wired yet.
        _ = await manager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
        return true;
    }

    private async Task<UserManager<RtUser>?> CreateManagerAsync(string tenantId)
    {
        var repository = await tenantRegistry.TryGetRepositoryAsync(tenantId);
        if (repository == null)
        {
            logger.LogWarning("Cross-tenant second factor refused: tenant '{TenantId}' is not registered", tenantId);
            return null;
        }

        // Role resolution is never used by the 2FA calls; the resolver is only there to satisfy the store.
        var store = new OctoUserStore(new FixedTenantResolver(repository), groupRoleResolver, errorDescriber);
        // OctoUserManager: atomic failure counting and recovery-code redemption, like the request-scoped manager.
        return new OctoUserManager(store, identityOptions, passwordHasher, userValidators, passwordValidators,
            keyNormalizer, errorDescriber, services, userManagerLogger);
    }

    /// <summary>Binds a store to one tenant repository, independent of the request's tenant.</summary>
    private sealed class FixedTenantResolver(ITenantRepository repository) : IMultiTenancyResolverService
    {
        public ITenantRepository GetTenantRepository() => repository;
        public string GetTenantId() => repository.TenantId;
    }
}
