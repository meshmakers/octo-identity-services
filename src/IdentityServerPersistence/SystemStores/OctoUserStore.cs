using System.Globalization;
using System.Security.Claims;
using IdentityServerPersistence.Services;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public sealed class OctoUserStore(
    IMultiTenancyResolverService multiTenancyResolverService,
    IGroupRoleResolver groupRoleResolver,
    IdentityErrorDescriber? describer)
    :
        IUserClaimStore<RtUser>,
        IUserLoginStore<RtUser>,
        IUserRoleStore<RtUser>,
        IUserPasswordStore<RtUser>,
        IUserSecurityStampStore<RtUser>,
        IUserEmailStore<RtUser>,
        IUserPhoneNumberStore<RtUser>,
        IUserTwoFactorStore<RtUser>,
        IUserLockoutStore<RtUser>,
        IUserAuthenticatorKeyStore<RtUser>,
        IUserAuthenticationTokenStore<RtUser>,
        IUserTwoFactorRecoveryCodeStore<RtUser>,
        IQueryableUserStore<RtUser>,
        IProtectedUserStore<RtUser>
{
    private const string InternalLoginProvider = "[AspNetUserStore]";
    private const string AuthenticatorKeyTokenName = "AuthenticatorKey";
    private const string RecoveryCodeTokenName = "RecoveryCodes";

    private ITenantRepository TenantRepository => multiTenancyResolverService.GetTenantRepository();
    private bool _disposed;

    private IdentityErrorDescriber ErrorDescriber { get; } = describer ?? new IdentityErrorDescriber();

    public IQueryable<RtUser> Users => TenantRepository.AsQueryable<RtUser>();

    public async Task SetTokenAsync(
        RtUser user,
        string loginProvider,
        string name,
        string? value,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        // Get the user from the database to modify its tokens
        var dbUser = await TenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, user.RtId);
        if (dbUser == null)
        {
            await session.AbortTransactionAsync();
            return;
        }

        var token = dbUser.UserTokens?.FirstOrDefault(x => x.LoginProvider == loginProvider && x.Name == name);

        // If value is null or empty, remove the token entirely
        if (string.IsNullOrEmpty(value))
        {
            if (token != null && dbUser.UserTokens != null)
            {
                dbUser.UserTokens.RemoveAll(x => x.LoginProvider == loginProvider && x.Name == name);
            }
        }
        else if (token == null)
        {
            dbUser.UserTokens ??= new AttributeRecordValueList<RtUserTokenRecord>();
            dbUser.UserTokens.Add(new RtUserTokenRecord
            {
                UserId = dbUser.RtId.ToString(),
                LoginProvider = loginProvider,
                Name = name,
                Value = value
            });
        }
        else
        {
            token.Value = value;
            var tokenIndex = dbUser.UserTokens!.FindIndex(x => x.LoginProvider == loginProvider && x.Name == name);
            dbUser.UserTokens[tokenIndex] = token;
        }

        // Persist the updated user back to the database
        await TenantRepository.ReplaceOneRtEntityByIdAsync(session, dbUser.RtId, dbUser);

        // Also update the in-memory user object
        user.UserTokens = dbUser.UserTokens;

        await session.CommitTransactionAsync();
    }

    public async Task RemoveTokenAsync(
        RtUser user,
        string loginProvider,
        string name,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        // Get the user from the database to modify its tokens
        var dbUser = await TenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, user.RtId);
        if (dbUser == null)
        {
            await session.AbortTransactionAsync();
            return;
        }

        var entry = dbUser.UserTokens?.FirstOrDefault(x => x.LoginProvider == loginProvider && x.Name == name);
        if (entry != null && dbUser.UserTokens != null)
        {
            dbUser.UserTokens.RemoveAll(x => x.LoginProvider == entry.LoginProvider && x.Name == entry.Name);

            // Persist the updated user back to the database
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, dbUser.RtId, dbUser);

            // Also update the in-memory user object
            user.UserTokens = dbUser.UserTokens;
        }

        await session.CommitTransactionAsync();
    }

    public async Task<string?> GetTokenAsync(
        RtUser user,
        string loginProvider,
        string name,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        ArgumentValidation.Validate(nameof(user), user);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var rtUserTokenRecord = await FindTokenAsync(session, user, loginProvider, name);

        await session.CommitTransactionAsync();

        // Return null if token doesn't exist - this is the expected behavior per ASP.NET Core Identity contract
        return rtUserTokenRecord?.Value;
    }

    public Task<string?> GetAuthenticatorKeyAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        return GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken);
    }

    public Task SetAuthenticatorKeyAsync(
        RtUser user,
        string key,
        CancellationToken cancellationToken = default)
    {
        return SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);
    }

    public async Task<IdentityResult> CreateAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        using var session = await TenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        await TenantRepository.InsertOneRtEntityAsync(session, user).ConfigureAwait(false);

        await session.CommitTransactionAsync().ConfigureAwait(false);
        return IdentityResult.Success;
    }

    public async Task<IdentityResult> DeleteAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        using var session = await TenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        try
        {
            await TenantRepository.DeleteOneRtEntityByRtIdAsync<RtUser>(session, user.RtId, DeleteOptions.Erase)
                .ConfigureAwait(false);
            await session.CommitTransactionAsync().ConfigureAwait(false);
            return IdentityResult.Success;
        }
        catch (PersistenceException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
    }

    public Task<RtUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return GetUserByIdAsync(ConvertIdFromString(userId), cancellationToken);
    }

    public async Task<RtUser?> FindByNameAsync(
        string normalizedUserName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        using var session = await TenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtUser.NormalizedUserName), FieldFilterOperator.Equals, normalizedUserName);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, queryOptions);

        await session.CommitTransactionAsync();

        return result.Items.FirstOrDefault();
    }

    public async Task<IdentityResult> UpdateAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        using var session = await TenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        try
        {
            await TenantRepository.ReplaceOneRtEntityByIdAsync(session, user.RtId, user).ConfigureAwait(false);
            await session.CommitTransactionAsync();
            return IdentityResult.Success;
        }
        catch (PersistenceException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }
    }

    public Task AddClaimsAsync(
        RtUser user,
        IEnumerable<Claim> claims,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);
        ArgumentValidation.Validate(nameof(claims), claims);

        foreach (var claim in claims)
        {
            var userClaim = new RtUserClaimRecord
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            };
            user.Claims ??= new AttributeRecordValueList<RtUserClaimRecord>();
            user.Claims.Add(userClaim);
        }

        return Task.FromResult(false);
    }

    public Task ReplaceClaimAsync(
        RtUser user,
        Claim claim,
        Claim newClaim,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        ArgumentValidation.Validate(nameof(user), user);
        ArgumentValidation.Validate(nameof(claim), claim);
        ArgumentValidation.Validate(nameof(newClaim), newClaim);

        if (user.Claims != null)
        {
            foreach (var userClaim in user.Claims
                         .Where(uc =>
                             uc.ClaimValue == claim.Value &&
                             uc.ClaimType == claim.Type)
                         .ToList())
            {
                userClaim.ClaimValue = newClaim.Value;
                userClaim.ClaimType = newClaim.Type;
            }
        }

        return Task.CompletedTask;
    }

    public Task RemoveClaimsAsync(
        RtUser user,
        IEnumerable<Claim> claims,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);
        ArgumentValidation.Validate(nameof(claims), claims);

        foreach (var claim1 in claims)
        {
            var claim = claim1;
            user.Claims?.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
        }

        return Task.CompletedTask;
    }

    public async Task<IList<RtUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(claim), claim);

        using var session = await TenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .MatchField(nameof(RtUser.Claims), FieldFilterCriteria.Create()
                .FieldEquals(nameof(RtUserClaimRecord.ClaimType), claim.Type)
                .FieldEquals(nameof(RtUserClaimRecord.ClaimValue), claim.Value));

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, queryOptions)
            .ConfigureAwait(false);

        await session.CommitTransactionAsync().ConfigureAwait(false);

        return result.Items.ToList();
    }

    public Task<string?> GetNormalizedUserNameAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.NormalizedUserName) : throw new ArgumentNullException(nameof(user));
    }

    public Task<string> GetUserIdAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null
            ? Task.FromResult(ConvertIdToString(user.RtId))
            : throw new ArgumentNullException(nameof(user));
    }

    public Task<string?> GetUserNameAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.UserName) : throw new ArgumentNullException(nameof(user));
    }

    public async Task<IList<Claim>> GetClaimsAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        ArgumentValidation.Validate(nameof(user), user);

        var dbUser = await GetUserByIdAsync(user.RtId, cancellationToken).ConfigureAwait(true);
        if (dbUser == null)
        {
            throw NotExistingException.UserWithIdDoesNotExist(user.RtId);
        }

        var source =
            dbUser.Claims?.Select(x => new Claim(x.ClaimType, x.ClaimValue));
        var claimsAsync = source?.ToList();

        return claimsAsync ?? new List<Claim>();
    }

    public Task SetNormalizedUserNameAsync(
        RtUser user,
        string? normalizedName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public Task SetUserNameAsync(RtUser user, string? userName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.UserName = userName;
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _disposed = true;
    }

    public Task<string?> GetEmailAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.Email) : throw new ArgumentNullException(nameof(user));
    }

    public Task<bool> GetEmailConfirmedAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.EmailConfirmed) : throw new ArgumentNullException(nameof(user));
    }

    public async Task<RtUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtUser.NormalizedEmail), FieldFilterOperator.Equals, normalizedEmail);

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, queryOptions);
        await session.CommitTransactionAsync();

        // Return null if user not found - per ASP.NET Core Identity IUserEmailStore contract
        return result.Items.FirstOrDefault();
    }

    public Task<string?> GetNormalizedEmailAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.NormalizedEmail) : throw new ArgumentNullException(nameof(user));
    }

    public Task SetEmailConfirmedAsync(
        RtUser user,
        bool confirmed,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.EmailConfirmed = confirmed;
        return Task.CompletedTask;
    }

    public Task SetNormalizedEmailAsync(
        RtUser user,
        string? normalizedEmail,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.NormalizedEmail = normalizedEmail;
        return Task.CompletedTask;
    }

    public Task SetEmailAsync(RtUser user, string? email, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.Email = email;
        return Task.CompletedTask;
    }

    public Task<int> GetAccessFailedCountAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.AccessFailedCount) : throw new ArgumentNullException(nameof(user));
    }

    public Task<bool> GetLockoutEnabledAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.LockoutEnabled) : throw new ArgumentNullException(nameof(user));
    }

    public Task<int> IncrementAccessFailedCountAsync(
        RtUser user,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        ++user.AccessFailedCount;
        return Task.FromResult(user.AccessFailedCount);
    }

    public Task ResetAccessFailedCountAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.AccessFailedCount = 0;
        return Task.CompletedTask;
    }

    public Task<DateTimeOffset?> GetLockoutEndDateAsync(
        RtUser user,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return Task.FromResult(user.LockoutEnd);
    }

    public Task SetLockoutEndDateAsync(
        RtUser user,
        DateTimeOffset? lockoutEnd,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.LockoutEnd = lockoutEnd;
        return Task.CompletedTask;
    }

    public Task SetLockoutEnabledAsync(
        RtUser user,
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.LockoutEnabled = enabled;
        return Task.CompletedTask;
    }

    public Task AddLoginAsync(RtUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);
        ArgumentValidation.Validate(nameof(login), login);

        var rtUserLoginRecord = new RtUserLoginRecord
        {
            UserId = ConvertIdToString(user.RtId),
            LoginProvider = login.LoginProvider,
            ProviderDisplayName = login.ProviderDisplayName,
            ProviderKey = login.ProviderKey
        };
        user.UserLogins ??= new AttributeRecordValueList<RtUserLoginRecord>();
        user.UserLogins.Add(rtUserLoginRecord);
        return Task.CompletedTask;
    }

    public Task RemoveLoginAsync(
        RtUser user,
        string loginProvider,
        string providerKey,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.UserLogins?.RemoveAll(x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey);
        return Task.CompletedTask;
    }

    public async Task<RtUser?> FindByLoginAsync(
        string loginProvider,
        string providerKey,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        using var session = await TenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        // Load all users and filter by UserLogins in C#.
        // The MatchField/ElemMatch query on embedded CK records does not
        // correctly resolve attribute paths, causing it to never match.
        var resultSet = await TenantRepository.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create())
            .ConfigureAwait(false);

        await session.CommitTransactionAsync();

        return resultSet.Items.FirstOrDefault(u =>
            u.UserLogins?.Any(l =>
                l.LoginProvider == loginProvider && l.ProviderKey == providerKey) == true);
    }

    public async Task<IList<UserLoginInfo>> GetLoginsAsync(
        RtUser user,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        var dbUser = await GetUserByIdAsync(user.RtId, cancellationToken).ConfigureAwait(false);
        if (dbUser == null)
        {
            throw NotExistingException.UserWithIdDoesNotExist(user.RtId);
        }

        var source = dbUser.UserLogins?.Select(x =>
            new UserLoginInfo(x.LoginProvider, x.ProviderKey, x.ProviderDisplayName));

        var userLoginInfos = source?.ToList() ?? new List<UserLoginInfo>();
        return userLoginInfos;
    }

    public Task<string?> GetPasswordHashAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        return Task.FromResult(user.PasswordHash);
    }

    public Task<bool> HasPasswordAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null
            ? Task.FromResult(user.PasswordHash != null)
            : throw new ArgumentNullException(nameof(user));
    }

    public Task SetPasswordHashAsync(
        RtUser user,
        string? passwordHash,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    public Task<string?> GetPhoneNumberAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.PhoneNumber) : throw new ArgumentNullException(nameof(user));
    }

    public Task<bool> GetPhoneNumberConfirmedAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null
            ? Task.FromResult(user.PhoneNumberConfirmed)
            : throw new ArgumentNullException(nameof(user));
    }

    public Task SetPhoneNumberAsync(
        RtUser user,
        string? phoneNumber,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.PhoneNumber = phoneNumber;
        return Task.CompletedTask;
    }

    public Task SetPhoneNumberConfirmedAsync(
        RtUser user,
        bool confirmed,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.PhoneNumberConfirmed = confirmed;
        return Task.CompletedTask;
    }

    public async Task AddToRoleAsync(
        RtUser user,
        string normalizedRoleName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);
        ArgumentValidation.ValidateString(nameof(normalizedRoleName), normalizedRoleName);

        var role = await FindRoleAsync(normalizedRoleName, cancellationToken) ??
                   throw new InvalidOperationException(string.Format(
                       CultureInfo.CurrentCulture, "Role {0} does not exist.",
                       normalizedRoleName));

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var userEntityId = user.ToRtEntityId();
        var roleEntityId = role.ToRtEntityId();

        // Check if already assigned
        var existing = await TenantRepository.GetRtAssociationOrDefaultAsync(
            session, userEntityId, roleEntityId, IdentityAssociationConstants.AssignedRoleId);
        if (existing == null)
        {
            var updates = new List<AssociationUpdateInfo>
            {
                AssociationUpdateInfo.CreateInsert(userEntityId, roleEntityId,
                    IdentityAssociationConstants.AssignedRoleId)
            };
            var opResult = new OperationResult();
            await TenantRepository.ApplyChangesAsync(session, updates, opResult);
        }

        await session.CommitTransactionAsync();
    }

    public async Task RemoveFromRoleAsync(
        RtUser user,
        string normalizedRoleName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);
        ArgumentValidation.ValidateString(nameof(normalizedRoleName), normalizedRoleName);

        var role = await FindRoleAsync(normalizedRoleName, cancellationToken);
        if (role == null)
        {
            return;
        }

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var updates = new List<AssociationUpdateInfo>
        {
            AssociationUpdateInfo.CreateDelete(
                user.ToRtEntityId(),
                role.ToRtEntityId(),
                IdentityAssociationConstants.AssignedRoleId)
        };
        var opResult = new OperationResult();
        await TenantRepository.ApplyChangesAsync(session, updates, opResult);

        await session.CommitTransactionAsync();
    }

    public async Task<IList<RtUser>> GetUsersInRoleAsync(
        string normalizedRoleName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        ArgumentValidation.ValidateString(nameof(normalizedRoleName), normalizedRoleName);

        var role = await FindRoleAsync(normalizedRoleName, cancellationToken);
        if (role == null)
        {
            return new List<RtUser>();
        }

        using var session = await TenantRepository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();

        // Query inbound AssignedRole associations on the role entity to find users assigned to it
        var associations = await TenantRepository.GetRtAssociationsAsync(
            session,
            role.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Inbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        var userCkTypeId = RtEntityExtensions.GetRtCkTypeId<RtUser>();
        var userRtIds = associations.Items
            .Where(a => a.OriginCkTypeId == userCkTypeId)
            .Select(a => a.OriginRtId)
            .ToList();

        var users = new List<RtUser>();
        foreach (var userRtId in userRtIds)
        {
            var user = await TenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, userRtId);
            if (user != null)
            {
                users.Add(user);
            }
        }

        await session.CommitTransactionAsync();

        return users;
    }

    public async Task<IList<string>> GetDirectRolesAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        ArgumentValidation.Validate(nameof(user), user);

        var dbUser = await GetUserByIdAsync(user.RtId, cancellationToken).ConfigureAwait(true);
        if (dbUser == null)
        {
            throw NotExistingException.UserWithIdDoesNotExist(user.RtId);
        }

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var associations = await TenantRepository.GetRtAssociationsAsync(
            session,
            dbUser.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        await session.CommitTransactionAsync();

        var roles = new List<string>();
        foreach (var assoc in associations.Items)
        {
            var role = await GetRoleByIdAsync(ConvertIdFromString(assoc.TargetRtId.ToString()), cancellationToken)
                .ConfigureAwait(true);
            if (!string.IsNullOrWhiteSpace(role.Name))
            {
                roles.Add(role.Name);
            }
        }

        return roles;
    }

    public async Task<IList<string>> GetRolesAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        ArgumentValidation.Validate(nameof(user), user);

        var dbUser = await GetUserByIdAsync(user.RtId, cancellationToken).ConfigureAwait(true);
        if (dbUser == null)
        {
            throw NotExistingException.UserWithIdDoesNotExist(user.RtId);
        }

        // Collect direct role IDs from AssignedRole associations
        var allRoleIds = new HashSet<string>();

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var associations = await TenantRepository.GetRtAssociationsAsync(
            session,
            dbUser.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(
                GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));

        await session.CommitTransactionAsync();

        foreach (var assoc in associations.Items)
        {
            allRoleIds.Add(assoc.TargetRtId.ToString());
        }

        // Merge group-inherited role IDs
        var groupRoleIds = await groupRoleResolver.ResolveEffectiveRoleIdsAsync(
            ConvertIdToString(dbUser.RtId));
        allRoleIds.UnionWith(groupRoleIds);

        // Resolve role IDs to role names
        var roles = new List<string>();
        foreach (var roleRtIdString in allRoleIds)
        {
            var role = await GetRoleByIdAsync(ConvertIdFromString(roleRtIdString), cancellationToken)
                .ConfigureAwait(true);
            if (!string.IsNullOrWhiteSpace(role.Name))
            {
                roles.Add(role.Name);
            }
        }

        return roles;
    }

    public async Task<bool> IsInRoleAsync(
        RtUser user,
        string normalizedRoleName,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        var dbUser = await GetUserByIdAsync(user.RtId, cancellationToken).ConfigureAwait(true);
        if (dbUser == null)
        {
            throw NotExistingException.UserWithIdDoesNotExist(user.RtId);
        }

        var role = await FindRoleAsync(normalizedRoleName, cancellationToken).ConfigureAwait(true);

        if (role == null)
        {
            return false;
        }

        var roleIdString = ConvertIdToString(role.RtId);

        // Check direct role assignment via AssignedRole association
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var existing = await TenantRepository.GetRtAssociationOrDefaultAsync(
            session, dbUser.ToRtEntityId(), role.ToRtEntityId(),
            IdentityAssociationConstants.AssignedRoleId);

        await session.CommitTransactionAsync();

        if (existing != null)
        {
            return true;
        }

        // Check group-inherited roles
        var groupRoleIds = await groupRoleResolver.ResolveEffectiveRoleIdsAsync(
            ConvertIdToString(dbUser.RtId));
        return groupRoleIds.Contains(roleIdString);
    }

    public Task<string?> GetSecurityStampAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.SecurityStamp) : throw new ArgumentNullException(nameof(user));
    }

    public Task SetSecurityStampAsync(
        RtUser user,
        string stamp,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.SecurityStamp = stamp != null ? stamp : throw new ArgumentNullException(nameof(stamp));
        return Task.CompletedTask;
    }

    public Task ReplaceCodesAsync(
        RtUser user,
        IEnumerable<string> recoveryCodes,
        CancellationToken cancellationToken = default)
    {
        // Normalize codes to match how ASP.NET Core Identity normalizes them during redemption
        // (upper case, no hyphens or spaces)
        var normalizedCodes = recoveryCodes.Select(c => c.ToUpperInvariant().Replace("-", "").Replace(" ", ""));
        var str = string.Join(";", normalizedCodes);
        return SetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, str, cancellationToken);
    }

    public async Task<bool> RedeemCodeAsync(
        RtUser user,
        string code,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);
        ArgumentValidation.ValidateString(nameof(code), code);

        var token = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken);
        var source = token?.Split(';');
        if (source == null || !source.Contains(code))
        {
            return false;
        }


        var recoveryCodes = new List<string>(source.Where(s => s != code));
        await ReplaceCodesAsync(user, recoveryCodes, cancellationToken);
        return true;
    }

    public async Task<int> CountCodesAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        var str = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken);
        return str == null || str.Length <= 0 ? 0 : str.Split(';').Length;
    }

    public Task<bool> GetTwoFactorEnabledAsync(RtUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return user != null ? Task.FromResult(user.TwoFactorEnabled) : throw new ArgumentNullException(nameof(user));
    }

    public Task SetTwoFactorEnabledAsync(
        RtUser user,
        bool enabled,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentValidation.Validate(nameof(user), user);

        user.TwoFactorEnabled = enabled;
        return Task.CompletedTask;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }

    private static OctoObjectId ConvertIdFromString(string id)
    {
        return new OctoObjectId(id);
    }

    private static string ConvertIdToString(OctoObjectId id)
    {
        return id.ToString();
    }

    private async Task<RtRole?> FindRoleAsync(
        string normalizedRoleName,
        CancellationToken cancellationToken = default)
    {
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, normalizedRoleName);

        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();

        var result = await TenantRepository.GetRtEntitiesByTypeAsync<RtRole>(session, queryOptions);
        cancellationToken.ThrowIfCancellationRequested();

        await session.CommitTransactionAsync();
        return result.Items.FirstOrDefault();
    }

    private async Task<RtUserTokenRecord?> FindTokenAsync(
        IOctoSession session,
        RtUser user,
        string loginProvider,
        string name)
    {
        var local = await TenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, user.RtId).ConfigureAwait(false);
        var tokenAsync = local?.UserTokens?.FirstOrDefault(x => x.LoginProvider == loginProvider && x.Name == name);

        return tokenAsync;
    }

    private async Task<RtUser?> GetUserByIdAsync(OctoObjectId rtId,
        CancellationToken cancellationToken = default)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();


        var result = await TenantRepository.GetRtEntityByRtIdAsync<RtUser>(session, rtId);
        cancellationToken.ThrowIfCancellationRequested();

        await session.CommitTransactionAsync();

        return result;
    }

    private async Task<RtRole> GetRoleByIdAsync(OctoObjectId rtId,
        CancellationToken cancellationToken = default)
    {
        using var session = await TenantRepository.GetSessionAsync();
        session.StartTransaction();


        var result = await TenantRepository.GetRtEntityByRtIdAsync<RtRole>(session, rtId);
        cancellationToken.ThrowIfCancellationRequested();

        await session.CommitTransactionAsync();

        return result ?? throw NotExistingException.RoleWithIdDoesNotExist(rtId);
    }
}