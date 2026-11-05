using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization;

/// <summary>
///     Writes the reason of a refused <see cref="IdentityApiRoleRequirement" /> into the <c>403</c> response (AB#5861), in
///     the shape of the tenant gate's denials (AB#5227) and of octo-common-services' <c>ForbiddenReasonAuthorizationResultHandler</c>
///     (AB#7319): a JSON body <c>{"message": "..."}</c> that names the missing role. The frontends' HTTP error interceptor
///     shows it instead of the generic access-denied text, octo-cli prints it. Every other outcome (401, scope-only
///     refusals, success) is left to the framework's default handler.
/// </summary>
internal sealed class IdentityApiForbiddenReasonResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _default = new();

    /// <inheritdoc />
    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Forbidden && !context.Response.HasStarted)
        {
            var reason = authorizeResult.AuthorizationFailure?.FailureReasons
                .FirstOrDefault(r => r.Handler is IdentityApiRoleAuthorizationHandler);
            if (reason != null)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new { message = reason.Message });
                return;
            }
        }

        await _default.HandleAsync(next, context, policy, authorizeResult);
    }
}
