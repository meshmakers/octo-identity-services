using Shared.TestUtilities.Builders;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServices.IntegrationTests.Helpers;

/// <summary>
/// Factory for creating test persisted grants with various configurations.
/// </summary>
public static class TestGrants
{
    /// <summary>
    /// Creates a refresh token grant.
    /// </summary>
    public static RtPersistedGrant CreateRefreshToken(
        string subjectId,
        string clientId,
        TimeSpan? lifetime = null) =>
        new RtPersistedGrantBuilder()
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .AsRefreshToken()
            .WithExpiration(DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromDays(30)))
            .Build();

    /// <summary>
    /// Creates an authorization code grant.
    /// </summary>
    public static RtPersistedGrant CreateAuthorizationCode(
        string subjectId,
        string clientId) =>
        new RtPersistedGrantBuilder()
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .AsAuthorizationCode()
            .Build();

    /// <summary>
    /// Creates a reference token grant.
    /// </summary>
    public static RtPersistedGrant CreateReferenceToken(
        string subjectId,
        string clientId) =>
        new RtPersistedGrantBuilder()
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .AsReferenceToken()
            .Build();

    /// <summary>
    /// Creates an expired grant.
    /// </summary>
    public static RtPersistedGrant CreateExpiredGrant(
        string subjectId,
        string clientId) =>
        new RtPersistedGrantBuilder()
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .AsRefreshToken()
            .Expired()
            .Build();

    /// <summary>
    /// Creates a consumed (already used) grant.
    /// </summary>
    public static RtPersistedGrant CreateConsumedGrant(
        string subjectId,
        string clientId) =>
        new RtPersistedGrantBuilder()
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .AsRefreshToken()
            .Consumed()
            .Build();

    /// <summary>
    /// Creates a grant with a specific session ID.
    /// </summary>
    public static RtPersistedGrant CreateGrantWithSession(
        string subjectId,
        string clientId,
        string sessionId) =>
        new RtPersistedGrantBuilder()
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .WithSessionId(sessionId)
            .AsRefreshToken()
            .Build();
}
