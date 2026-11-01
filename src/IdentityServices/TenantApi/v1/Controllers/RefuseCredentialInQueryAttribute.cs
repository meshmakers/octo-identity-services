using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     Refuses a request that carries a credential as a URL query parameter (AB#8008), with 400 and a hint to update the
///     client. The value is never read into a model, never logged and never echoed.
/// </summary>
/// <remarks>
///     <para>
///         A resource filter: it runs after authorization and before model binding, so an outdated client gets this
///         answer instead of a model-binding or media-type error, and the action (with its TRACE argument log) never
///         runs.
///     </para>
///     <para>
///         The single place of the refusal: older clients (octo-cli, the SDK, Refinery Studio before the AB#8008
///         update) sent <c>POST users/ResetPassword?userName=…&amp;password=…</c>.
///     </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Method)]
public sealed class RefuseCredentialInQueryAttribute(params string[] parameterNames) : Attribute, IResourceFilter
{
    /// <summary>The answer an outdated client gets.</summary>
    internal const string Message =
        "Credentials are no longer accepted as URL query parameters. Send them in the JSON request body " +
        "(update octo-cli, the OctoMesh SDK or Refinery Studio to the current version).";

    /// <inheritdoc />
    public void OnResourceExecuting(ResourceExecutingContext context)
    {
        var query = context.HttpContext.Request.Query;
        if (parameterNames.Any(query.ContainsKey))
        {
            context.Result = new BadRequestObjectResult(new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Credential in the request URL",
                Detail = Message
            });
        }
    }

    /// <inheritdoc />
    public void OnResourceExecuted(ResourceExecutedContext context)
    {
    }
}
