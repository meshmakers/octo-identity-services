using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// RFC 9457 problem responses of <c>POST {tenant}/v1/users</c> (duplicate e-mail AB#8064, duplicate user name AB#8083) and
/// <c>PUT {tenant}/v1/users/{userName}</c> when the e-mail address (AB#8084) or the user name (AB#8083) changes. The <c>code</c> extension carries the same
/// language-neutral code as the declared error of the CK method <c>User.CreateUser-1</c>; the title is a readable sentence
/// that Studio shows unchanged.
/// </summary>
public static class UserCreationProblems
{
    /// <summary>Code of the 409 answer: another user of the tenant already has this user name or e-mail address.</summary>
    public const string UserAlreadyExistsCode = "USER_ALREADY_EXISTS";

    /// <summary>Value of the <c>field</c> extension for a duplicate e-mail address.</summary>
    public const string EmailField = "email";

    /// <summary>Value of the <c>field</c> extension for a duplicate user name.</summary>
    public const string UserNameField = "userName";

    /// <summary>
    /// Builds the 409 <c>application/problem+json</c> answer for a duplicate user name (AB#8083). The name itself is not
    /// repeated (the caller sent it); the answer names only the field.
    /// </summary>
    public static ObjectResult DuplicateUserName() =>
        Conflict("Another user of this tenant already has this user name.",
            "Use a different user name, or edit the existing user instead of creating a second one.", UserNameField);

    /// <summary>
    /// Builds the 409 <c>application/problem+json</c> answer for a duplicate e-mail address. The address itself is not
    /// repeated (the caller sent it); the answer names only the field.
    /// </summary>
    public static ObjectResult DuplicateEmail() =>
        Conflict("Another user of this tenant already has this e-mail address.",
            "Use a different e-mail address, or edit the existing user instead of creating a second one.", EmailField);

    private static ObjectResult Conflict(string title, string detail, string field)
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status409Conflict,
            Title = title,
            Detail = detail,
            Extensions =
            {
                ["code"] = UserAlreadyExistsCode,
                ["field"] = field
            }
        };
        return new ObjectResult(problem)
        {
            StatusCode = StatusCodes.Status409Conflict,
            ContentTypes = { "application/problem+json" }
        };
    }
}
