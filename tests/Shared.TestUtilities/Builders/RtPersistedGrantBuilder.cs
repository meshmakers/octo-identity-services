using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Shared.TestUtilities.Builders;

/// <summary>
/// Fluent builder for creating RtPersistedGrant test entities.
/// </summary>
public class RtPersistedGrantBuilder
{
    private readonly RtPersistedGrant _grant = new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        GrantKey = Guid.NewGuid().ToString("N"),
        GrantType = "refresh_token",
        SubjectId = "default-subject",
        ClientId = "default-client",
        CreationDateTime = DateTime.UtcNow,
        ExpirationDateTime = DateTime.UtcNow.AddDays(30),
        Data = "{}"
    };

    public RtPersistedGrantBuilder WithRtId(OctoObjectId rtId)
    {
        _grant.RtId = rtId;
        return this;
    }

    public RtPersistedGrantBuilder WithKey(string key)
    {
        _grant.GrantKey = key;
        return this;
    }

    public RtPersistedGrantBuilder WithGrantType(string grantType)
    {
        _grant.GrantType = grantType;
        return this;
    }

    public RtPersistedGrantBuilder WithSubjectId(string subjectId)
    {
        _grant.SubjectId = subjectId;
        return this;
    }

    public RtPersistedGrantBuilder WithClientId(string clientId)
    {
        _grant.ClientId = clientId;
        return this;
    }

    public RtPersistedGrantBuilder WithSessionId(string sessionId)
    {
        _grant.SessionId = sessionId;
        return this;
    }

    public RtPersistedGrantBuilder WithCreationTime(DateTime creationTime)
    {
        _grant.CreationDateTime = creationTime;
        return this;
    }

    public RtPersistedGrantBuilder WithExpiration(DateTime expiration)
    {
        _grant.ExpirationDateTime = expiration;
        return this;
    }

    public RtPersistedGrantBuilder WithConsumedTime(DateTime? consumedTime)
    {
        _grant.ConsumedDateTime = consumedTime;
        return this;
    }

    public RtPersistedGrantBuilder WithDescription(string description)
    {
        _grant.Description = description;
        return this;
    }

    public RtPersistedGrantBuilder WithData(string data)
    {
        _grant.Data = data;
        return this;
    }

    /// <summary>
    /// Creates a refresh token grant with default settings.
    /// </summary>
    public RtPersistedGrantBuilder AsRefreshToken()
    {
        _grant.GrantType = "refresh_token";
        _grant.ExpirationDateTime = DateTime.UtcNow.AddDays(30);
        return this;
    }

    /// <summary>
    /// Creates an authorization code grant with default settings.
    /// </summary>
    public RtPersistedGrantBuilder AsAuthorizationCode()
    {
        _grant.GrantType = "authorization_code";
        _grant.ExpirationDateTime = DateTime.UtcNow.AddMinutes(5);
        return this;
    }

    /// <summary>
    /// Creates a reference token grant with default settings.
    /// </summary>
    public RtPersistedGrantBuilder AsReferenceToken()
    {
        _grant.GrantType = "reference_token";
        _grant.ExpirationDateTime = DateTime.UtcNow.AddHours(1);
        return this;
    }

    /// <summary>
    /// Creates an expired grant.
    /// </summary>
    public RtPersistedGrantBuilder Expired()
    {
        _grant.ExpirationDateTime = DateTime.UtcNow.AddDays(-1);
        return this;
    }

    /// <summary>
    /// Creates a consumed grant.
    /// </summary>
    public RtPersistedGrantBuilder Consumed()
    {
        _grant.ConsumedDateTime = DateTime.UtcNow;
        return this;
    }

    public RtPersistedGrant Build() => _grant;
}
