namespace IdentityServerPersistence.Services;

/// <summary>
/// Result of a cross-tenant authentication attempt.
/// Contains the source user information and the tenant where the user was found.
/// </summary>
public class CrossTenantAuthResult
{
    /// <summary>
    /// The tenant ID where the user's account resides.
    /// </summary>
    public required string SourceTenantId { get; init; }

    /// <summary>
    /// The RtId of the user in the source tenant.
    /// </summary>
    public required string SourceUserId { get; init; }

    /// <summary>
    /// The username in the source tenant.
    /// </summary>
    public required string SourceUserName { get; init; }

    /// <summary>
    /// The user's first name.
    /// </summary>
    public string? FirstName { get; init; }

    /// <summary>
    /// The user's last name.
    /// </summary>
    public string? LastName { get; init; }

    /// <summary>
    /// The user's email address.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// <c>true</c> when the source user — or any identity its <c>xt_</c> chain unwinds to — has two-factor
    /// authentication enabled (AB#7804). A cross-tenant sign-in for such a user must not create a session or a
    /// token in the target tenant without second-factor evidence (see <see cref="SecondFactorEvidence" />).
    /// </summary>
    public bool SourceUserRequiresSecondFactor { get; init; }
}
