using System.Globalization;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// RFC 9457 problem answers of <c>POST ExternalTenantUserMappings/sourceUserLookup</c> (AB#8341, contract
/// <c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §3–§5). Codes come from <see cref="CrossTenantGrantProblemCodes" />.
/// </summary>
public static class SourceUserLookupProblems
{
    /// <summary>
    /// The one <c>404</c> of every negative case. Constant: it names neither the tenant nor the identifier, so the body
    /// never tells the cases apart.
    /// </summary>
    public static ObjectResult NotFound()
        => Problem(StatusCodes.Status404NotFound, CrossTenantGrantProblemCodes.SourceUserNotFound,
            "Source user not found",
            "No user of the source tenant can be granted access with this identifier.");

    /// <summary>
    /// The <c>429</c> of the lookup limit. The wait time is in the <c>Retry-After</c> header (set by the caller) and in
    /// the body field <c>retryAfterSeconds</c>, which a browser can read across origins.
    /// </summary>
    public static ObjectResult RateLimited(HttpResponse response, int retryAfterSeconds)
    {
        response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        var result = Problem(StatusCodes.Status429TooManyRequests,
            CrossTenantGrantProblemCodes.SourceUserLookupRateLimited, "Too many lookups",
            "Too many source user lookups. Try again later.");
        ((ProblemDetails)result.Value!).Extensions["retryAfterSeconds"] = retryAfterSeconds;
        return result;
    }

    private static ObjectResult Problem(int status, string code, string title, string detail)
    {
        var problem = new ProblemDetails
        {
            Status = status,
            Title = title,
            Detail = detail,
            Extensions = { ["code"] = code }
        };
        return new ObjectResult(problem)
        {
            StatusCode = status,
            ContentTypes = { "application/problem+json" }
        };
    }
}
