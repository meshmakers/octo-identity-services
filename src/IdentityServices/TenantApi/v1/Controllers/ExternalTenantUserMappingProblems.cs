using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// RFC 9457 problem responses of the external-tenant-user-mapping endpoints. The <c>code</c> extension is
/// language-neutral and stable; clients branch on it, the English title and detail are for humans (AB#6975).
/// </summary>
public static class ExternalTenantUserMappingProblems
{
    /// <summary>Code of the 409 answer when a mapping for the (source tenant, source user) pair already exists.</summary>
    public const string AlreadyExistsCode = "ExternalTenantUserMappingAlreadyExists";

    /// <summary>Builds the 409 <c>application/problem+json</c> answer naming the existing mapping.</summary>
    public static ObjectResult AlreadyExists(
        RtExternalTenantUserMapping existing, string sourceTenantId, string sourceUserId)
    {
        var existingId = existing.RtId.ToString();
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status409Conflict,
            Title = "A mapping for this source user already exists",
            Detail = $"Mapping '{existingId}' already maps user '{sourceUserId}' of source tenant '{sourceTenantId}'. " +
                     "Update its roles (PUT ExternalTenantUserMappings/{id}) instead of creating a second mapping.",
            Extensions =
            {
                ["code"] = AlreadyExistsCode,
                ["existingMappingId"] = existingId
            }
        };
        return new ObjectResult(problem)
        {
            StatusCode = StatusCodes.Status409Conflict,
            ContentTypes = { "application/problem+json" }
        };
    }

    /// <summary>
    /// The one <c>403</c> of every refused source (AB#8343): source tenant unknown, neither a registry ancestor of the
    /// target nor permitting it, or the user absent or blocked there. Constant body, so it never tells the cases apart.
    /// </summary>
    public static ObjectResult SourceTenantNotPermitted()
        => Problem(StatusCodes.Status403Forbidden, CrossTenantGrantProblemCodes.SourceTenantNotPermitted,
            "Source tenant not permitted",
            "No user of the source tenant can be granted access to this tenant with this request.");

    /// <summary>
    /// The <c>400</c> when <c>groupIds</c> names groups this tenant does not have (AB#8343); nothing was stored.
    /// </summary>
    public static ObjectResult UnknownGroup(IReadOnlyList<string> unknownGroupIds)
    {
        var result = Problem(StatusCodes.Status400BadRequest, CrossTenantGrantProblemCodes.UnknownGroup,
            "Unknown group",
            "One or more group ids are no group of this tenant. Nothing was stored.");
        ((ProblemDetails)result.Value!).Extensions["unknownGroupIds"] = unknownGroupIds;
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
