using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// RFC 9457 problem responses when a request names a tenant as cross-tenant ancestor that the tenant registry does not
/// confirm (AB#8339, only under <c>IdentityApiAuthorization:CrossTenantAncestry=Enforce</c>). The <c>code</c> extension is
/// language-neutral and stable; clients branch on it, the English title and detail are for humans.
/// </summary>
public static class CrossTenantAncestryProblems
{
    /// <summary>
    /// Code of the 403 answer of the admin provisioning writes when the mapping's <c>SourceTenantId</c> is no registry
    /// ancestor of the target tenant.
    /// </summary>
    public const string SourceTenantNotAncestorCode = "CrossTenantSourceNotAncestor";

    /// <summary>
    /// Code of the 400 answer of the identity provider writes when an OctoTenant provider's <c>ParentTenantId</c> is no
    /// registry ancestor of the tenant it is stored in.
    /// </summary>
    public const string ParentTenantNotAncestorCode = "OctoTenantParentNotAncestor";

    /// <summary>Builds the 403 answer of the admin provisioning writes.</summary>
    public static ObjectResult SourceTenantNotAncestor(string targetTenantId, string sourceTenantId)
        => Problem(StatusCodes.Status403Forbidden, SourceTenantNotAncestorCode,
            "The source tenant is not an ancestor of the target tenant",
            $"Tenant '{sourceTenantId}' is not a parent or other ancestor of tenant '{targetTenantId}' in the tenant " +
            "registry. Users of a tenant outside the ancestor chain cannot be admitted without that tenant's permission.");

    /// <summary>Builds the 400 answer of the identity provider writes.</summary>
    public static ObjectResult ParentTenantNotAncestor(string tenantId, string parentTenantId)
        => Problem(StatusCodes.Status400BadRequest, ParentTenantNotAncestorCode,
            "The parent tenant is not an ancestor of this tenant",
            $"Tenant '{parentTenantId}' is not a parent or other ancestor of tenant '{tenantId}' in the tenant " +
            "registry. An OctoTenant identity provider may only name a registry ancestor.");

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
