namespace IdentityServerPersistence.Services;

/// <summary>
/// Service that authenticates users by walking up the tenant hierarchy.
/// When a user logs in to a child tenant, and the child tenant has an
/// OctoTenantIdentityProvider configured, the service will try to validate
/// credentials against the parent tenant's user database.
/// </summary>
public interface ICrossTenantAuthenticationService
{
    /// <summary>
    /// Attempts to authenticate a user by walking up the tenant hierarchy.
    /// Returns the authenticated user info and the tenant where they were found,
    /// or null if authentication fails.
    /// </summary>
    /// <param name="childTenantId">The tenant the user is logging in to.</param>
    /// <param name="username">The username to authenticate.</param>
    /// <param name="password">The password to validate.</param>
    /// <returns>The authentication result, or null if no match found.</returns>
    Task<CrossTenantAuthResult?> AuthenticateAsync(
        string childTenantId, string username, string password);

    /// <summary>
    /// Validates whether an already-authenticated user from a source tenant
    /// can access the target tenant (for tenant-switch flow).
    /// Walks up the hierarchy from the target tenant to verify the source tenant
    /// is an ancestor.
    /// </summary>
    /// <param name="targetTenantId">The tenant the user wants to switch to.</param>
    /// <param name="sourceTenantId">The tenant where the user is currently authenticated.</param>
    /// <param name="sourceUserId">The RtId of the user in the source tenant.</param>
    /// <returns>The authentication result, or null if access is denied.</returns>
    Task<CrossTenantAuthResult?> ValidateCrossTenantAccessAsync(
        string targetTenantId, string sourceTenantId, string sourceUserId);
}
