using System.ComponentModel.DataAnnotations;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     Request body of the administrator password reset <c>POST {tenant}/v1/users/ResetPassword</c> (AB#8008). The new
///     password travels only in the body: a URL ends up in request logs, traces and proxy access logs, a body does not.
/// </summary>
/// <remarks>
///     A class with its own <see cref="ToString" />, not a record: ASP.NET Core writes the action arguments with
///     <c>ToString()</c> into its TRACE log, and the compiler-generated <c>ToString()</c> of a record prints every
///     property, the password included.
/// </remarks>
public sealed class ResetUserPasswordRequestDto
{
    /// <summary>The user name of the user whose password is reset.</summary>
    [Required]
    public string UserName { get; set; } = string.Empty;

    /// <summary>The new password. Never logged, never echoed.</summary>
    [Required]
    public string Password { get; set; } = string.Empty;

    /// <summary>Names the user only; the password is never part of the text.</summary>
    public override string ToString() => $"{nameof(ResetUserPasswordRequestDto)} {{ UserName = {UserName} }}";
}
