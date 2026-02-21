using Microsoft.AspNetCore.Identity;

namespace Meshmakers.Octo.Backend.Authentication.Services;

/// <summary>
/// Service for authenticating users against LDAP providers (OpenLDAP, Microsoft AD)
/// </summary>
public interface ILdapAuthenticationService
{
    /// <summary>
    /// Authenticates a user against the specified LDAP provider scheme
    /// </summary>
    /// <param name="scheme">The authentication scheme name (provider identifier)</param>
    /// <param name="username">The username or email to authenticate</param>
    /// <param name="password">The password</param>
    /// <returns>Authentication result with external login info on success</returns>
    Task<LdapAuthenticationResult> AuthenticateAsync(string scheme, string username, string password);

    /// <summary>
    /// Checks if the specified scheme is an LDAP-based authentication scheme
    /// </summary>
    /// <param name="scheme">The scheme name to check</param>
    /// <returns>True if the scheme is LDAP-based</returns>
    Task<bool> IsLdapSchemeAsync(string scheme);
}

/// <summary>
/// Result of LDAP authentication attempt
/// </summary>
public record LdapAuthenticationResult
{
    /// <summary>
    /// Whether authentication was successful
    /// </summary>
    public bool Succeeded { get; init; }

    /// <summary>
    /// External login info if authentication succeeded
    /// </summary>
    public ExternalLoginInfo? LoginInfo { get; init; }

    /// <summary>
    /// Error message if authentication failed
    /// </summary>
    public string? ErrorMessage { get; init; }

    public static LdapAuthenticationResult Success(ExternalLoginInfo loginInfo) =>
        new() { Succeeded = true, LoginInfo = loginInfo };

    public static LdapAuthenticationResult Failure(string errorMessage) =>
        new() { Succeeded = false, ErrorMessage = errorMessage };
}
