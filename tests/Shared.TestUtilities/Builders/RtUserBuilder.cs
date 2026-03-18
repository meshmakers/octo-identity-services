using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Shared.TestUtilities.Builders;

public class RtUserBuilder
{
    private readonly RtUser _user = new()
    {
        RtId = new OctoObjectId(Guid.NewGuid().ToString("N")),
        UserName = "defaultuser",
        Email = "default@test.com",
        NormalizedUserName = "DEFAULTUSER",
        NormalizedEmail = "DEFAULT@TEST.COM",
        EmailConfirmed = true,
        SecurityStamp = Guid.NewGuid().ToString(),
        FirstName = "Default",
        LastName = "User"
    };

    public RtUserBuilder WithRtId(OctoObjectId rtId)
    {
        _user.RtId = rtId;
        return this;
    }

    public RtUserBuilder WithUserName(string userName)
    {
        _user.UserName = userName;
        _user.NormalizedUserName = userName.ToUpperInvariant();
        return this;
    }

    public RtUserBuilder WithEmail(string email)
    {
        _user.Email = email;
        _user.NormalizedEmail = email.ToUpperInvariant();
        return this;
    }

    public RtUserBuilder WithFirstName(string firstName)
    {
        _user.FirstName = firstName;
        return this;
    }

    public RtUserBuilder WithLastName(string lastName)
    {
        _user.LastName = lastName;
        return this;
    }

    public RtUserBuilder WithPasswordHash(string passwordHash)
    {
        _user.PasswordHash = passwordHash;
        return this;
    }

    public RtUserBuilder WithTwoFactorEnabled(bool enabled = true)
    {
        _user.TwoFactorEnabled = enabled;
        return this;
    }

    public RtUserBuilder WithEmailConfirmed(bool confirmed = true)
    {
        _user.EmailConfirmed = confirmed;
        return this;
    }

    public RtUserBuilder WithLockedOut(DateTimeOffset? lockoutEnd = null)
    {
        _user.LockoutEnabled = true;
        _user.LockoutEnd = lockoutEnd ?? DateTimeOffset.UtcNow.AddHours(1);
        return this;
    }

    public RtUserBuilder WithAccessFailedCount(int count)
    {
        _user.AccessFailedCount = count;
        return this;
    }

    public RtUserBuilder WithClaim(string type, string value)
    {
        _user.Claims ??= new AttributeRecordValueList<RtUserClaimRecord>();
        _user.Claims.Add(new RtUserClaimRecord
        {
            ClaimType = type,
            ClaimValue = value
        });
        return this;
    }

    public RtUserBuilder WithLogin(string loginProvider, string providerKey, string displayName)
    {
        _user.UserLogins ??= new AttributeRecordValueList<RtUserLoginRecord>();
        _user.UserLogins.Add(new RtUserLoginRecord
        {
            LoginProvider = loginProvider,
            ProviderKey = providerKey,
            ProviderDisplayName = displayName,
            UserId = _user.RtId.ToString()
        });
        return this;
    }

    public RtUserBuilder WithAuthenticatorKey(string key)
    {
        _user.UserTokens ??= new AttributeRecordValueList<RtUserTokenRecord>();
        _user.UserTokens.Add(new RtUserTokenRecord
        {
            LoginProvider = "[AspNetUserStore]",
            Name = "AuthenticatorKey",
            Value = key
        });
        return this;
    }

    public RtUserBuilder WithRecoveryCodes(IEnumerable<string> codes)
    {
        _user.UserTokens ??= new AttributeRecordValueList<RtUserTokenRecord>();
        _user.UserTokens.Add(new RtUserTokenRecord
        {
            LoginProvider = "[AspNetUserStore]",
            Name = "RecoveryCodes",
            Value = string.Join(";", codes)
        });
        return this;
    }

    public RtUser Build() => _user;
}
