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
}
