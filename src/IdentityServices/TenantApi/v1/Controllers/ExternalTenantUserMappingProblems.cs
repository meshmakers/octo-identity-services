using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

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
}
