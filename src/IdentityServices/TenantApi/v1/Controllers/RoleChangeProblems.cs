using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// RFC 9457 problem responses of refused role changes (AB#7914). The <c>code</c> extension is language-neutral and
/// stable (<see cref="RoleChangeReasons" />); the title is a readable sentence that Studio shows unchanged.
/// </summary>
public static class RoleChangeProblems
{
    /// <summary>Event name of the audit record written for every refused role change.</summary>
    public const string AuditEventName = "Identity.RoleChangeRefused";

    /// <summary>403 for <c>self-grant</c> and <c>role-not-held</c>, 409 for <c>last-administrator</c> and <c>built-in-role</c>.</summary>
    public static ObjectResult ToResult(RoleChangeDecision decision)
    {
        var status = decision.Reason is RoleChangeReasons.LastAdministrator or RoleChangeReasons.BuiltInRole
            ? StatusCodes.Status409Conflict
            : StatusCodes.Status403Forbidden;
        var problem = new ProblemDetails
        {
            Status = status,
            Title = decision.Title,
            Extensions = { ["code"] = decision.Reason }
        };
        if (decision.Reason is RoleChangeReasons.RoleNotHeld or RoleChangeReasons.BuiltInRole && decision.RoleNames.Count > 0)
        {
            problem.Extensions["roleNames"] = decision.RoleNames;
        }

        return new ObjectResult(problem)
        {
            StatusCode = status,
            ContentTypes = { "application/problem+json" }
        };
    }
}
