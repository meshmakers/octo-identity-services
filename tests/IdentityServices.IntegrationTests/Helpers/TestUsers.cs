using Shared.TestUtilities.Builders;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServices.IntegrationTests.Helpers;

/// <summary>
/// Factory for creating test users with various configurations.
/// </summary>
public static class TestUsers
{
    public const string DefaultPassword = "Test123!";

    /// <summary>
    /// Creates a standard user with email confirmed.
    /// </summary>
    public static RtUser CreateStandardUser(string userName = "testuser") =>
        new RtUserBuilder()
            .WithUserName(userName)
            .WithEmail($"{userName}@example.com")
            .WithEmailConfirmed()
            .Build();

    /// <summary>
    /// Creates a user that is locked out.
    /// </summary>
    public static RtUser CreateLockedOutUser() =>
        new RtUserBuilder()
            .WithUserName("lockeduser")
            .WithEmail("locked@example.com")
            .WithEmailConfirmed()
            .WithLockedOut(DateTimeOffset.UtcNow.AddHours(1))
            .Build();

    /// <summary>
    /// Creates a user with two-factor authentication enabled.
    /// </summary>
    public static RtUser CreateTwoFactorUser() =>
        new RtUserBuilder()
            .WithUserName("2fauser")
            .WithEmail("2fa@example.com")
            .WithEmailConfirmed()
            .WithTwoFactorEnabled()
            .Build();

    /// <summary>
    /// Creates a user with unconfirmed email.
    /// </summary>
    public static RtUser CreateUnconfirmedUser() =>
        new RtUserBuilder()
            .WithUserName("unconfirmed")
            .WithEmail("unconfirmed@example.com")
            .Build();

    /// <summary>
    /// Creates a user with specific credentials.
    /// </summary>
    public static RtUser CreateUserWithCredentials(string userName, string email) =>
        new RtUserBuilder()
            .WithUserName(userName)
            .WithEmail(email)
            .WithEmailConfirmed()
            .Build();
}
