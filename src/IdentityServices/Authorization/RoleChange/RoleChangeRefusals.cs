using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;

/// <summary>
///     Turns a refused role change of a REST endpoint into the problem answer (403 / 409) and writes the WARN log and the
///     <c>Identity.RoleChangeRefused</c> audit event (AB#7927; the same record as <c>UsersController</c> writes since AB#7914).
/// </summary>
public interface IRoleChangeRefusals
{
    /// <summary>Audits the refusal and returns the answer. <paramref name="target" /> names what was changed, e.g. <c>group 1234</c>.</summary>
    Task<ObjectResult> RefuseAsync(HttpContext http, RoleChangeCaller caller, RoleChangeDecision decision, string target);
}

internal sealed class RoleChangeRefusals(IIdentityAuditService auditService, ILogger<RoleChangeRefusals> logger)
    : IRoleChangeRefusals
{
    public async Task<ObjectResult> RefuseAsync(HttpContext http, RoleChangeCaller caller, RoleChangeDecision decision,
        string target)
    {
        var callerText = caller.Subject != null ? $"subject {caller.Subject}" : $"client {caller.ClientId}";
        var message =
            $"Role change refused ({decision.Reason}): caller {callerText}, target {target}, roles [{string.Join(",", decision.RoleNames)}], {http.Request.Method} {http.Request.Path.Value}";
        logger.LogWarning("{Message}", message);
        await auditService.StoreFailureAsync(RoleChangeProblems.AuditEventName, message).ConfigureAwait(false);
        return RoleChangeProblems.ToResult(decision);
    }
}
