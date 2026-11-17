using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Shared rules of the identity methods that write into another tenant than the one they run in (client mirrors in child
///     tenants, admin provisioning into a target tenant).
/// </summary>
internal static class CrossTenantMethodSupport
{
    /// <summary><c>reason</c> of the <c>METHOD_FORBIDDEN</c> answer for a target tenant outside the caller's tenant subtree.</summary>
    public const string TenantOutOfScopeReason = "tenant-out-of-scope";

    /// <summary>
    ///     The tenant the caller's token was issued for: its <c>tenant_id</c> claim (<see cref="CkMethodPrincipal.TokenTenantId" />,
    ///     set on the in-process and on the bus path), else the tenant the bus host validated the token for. Not the tenant
    ///     of the call: an allow-listed cross-tenant service client calls in other tenants, and the target rule must judge it
    ///     by its own tenant on every transport. <c>null</c> when neither is known (the target rule then refuses).
    /// </summary>
    public static string? CallerTenantId(CkMethodPrincipal principal) => principal.TokenTenantId ?? principal.TenantId;

    /// <summary>
    ///     The REST target rule (<see cref="AdminProvisioningTargetScope" />) on the method path: <paramref name="targetTenantId" />
    ///     must be the caller's tenant or lie in its subtree, else <c>METHOD_FORBIDDEN</c> (<c>reason</c> =
    ///     <see cref="TenantOutOfScopeReason" />). Returns <c>null</c> when allowed.
    /// </summary>
    /// <remarks>
    ///     <c>IdentityApiAuthorization:RoleEnforcement=Warn</c> stages the rule only for a call a REST facade of this process
    ///     made (<see cref="IsRestFacadeCall" />), exactly like <c>AdminProvisioningTargetScopeFilter</c>: logged and allowed,
    ///     so existing REST callers are surfaced, not broken. A call that arrived over the bus (the GraphQL gateway, another
    ///     service) is a new path without existing callers and is refused in either mode.
    /// </remarks>
    public static async Task<CkMethodFailure?> CheckTargetTenantAsync(IdentityMethodCall call, string methodId,
        string? targetTenantId)
    {
        var services = call.Services;
        var callerTenantId = CallerTenantId(call.Principal);
        if (await AdminProvisioningTargetScope.IsInCallerScopeAsync(
                services.GetRequiredService<ITenantDiscoveryService>(),
                services.GetRequiredService<IOptions<OctoSystemConfiguration>>().Value.SystemTenantId, callerTenantId,
                targetTenantId).ConfigureAwait(false))
        {
            return null;
        }

        var logger = services.GetRequiredService<ILogger<IdentityMethodCall>>();
        if (IsRestFacadeCall(call.Principal) &&
            services.GetRequiredService<IOptionsMonitor<IdentityApiAuthorizationOptions>>().CurrentValue.RoleEnforcement ==
            IdentityApiRoleEnforcementMode.Warn)
        {
            logger.LogWarning(
                "Cross-tenant method {MethodId} outside the caller's tenant subtree allowed by RoleEnforcement=Warn for a REST call: caller tenant {CallerTenantId}, target tenant {TargetTenantId}. " +
                "This would be denied with RoleEnforcement=Enforce",
                methodId, callerTenantId, targetTenantId);
            return null;
        }

        logger.LogWarning(
            "Cross-tenant method {MethodId} denied, target outside the caller's tenant subtree: caller tenant {CallerTenantId}, target tenant {TargetTenantId}",
            methodId, callerTenantId, targetTenantId);
        return OutOfScope(call);
    }

    /// <summary>
    ///     <c>true</c> for a call a REST facade of this process made through the in-process transport: the principal is the
    ///     very object the facade built (<see cref="RestFacadePrincipals" />). Decided by the transport, not by the
    ///     principal's content: a bus call - with or without a tenant - is never a REST call.
    /// </summary>
    public static bool IsRestFacadeCall(CkMethodPrincipal principal) => RestFacadePrincipals.IsMarked(principal);

    /// <summary>The <c>METHOD_FORBIDDEN</c> answer for a target tenant outside the caller's (or the parent's) subtree.</summary>
    public static CkMethodFailure OutOfScope(IdentityMethodCall call)
    {
        call.Details["reason"] = TenantOutOfScopeReason;
        return new CkMethodFailure(CkMethodErrorCodes.MethodForbidden,
            new Dictionary<string, string> { ["reason"] = TenantOutOfScopeReason });
    }

    /// <summary>
    ///     The name of the caller for the cross-tenant grant audit events (<c>actorName</c>). The method caller carries no
    ///     profile claims, so: the client id of a service caller; else the user name stored for the subject in the caller's
    ///     token tenant (the name the identity service writes into the tokens it issues); else - a deleted user or a token
    ///     of another issuer - the subject, with a WARN line that names no user. Never empty, never a token.
    /// </summary>
    public static async Task<string> CallerNameAsync(IdentityMethodCall call, string callTenantId)
    {
        var principal = call.Principal;
        if (principal.IsServiceToken)
        {
            return principal.ClientId!;
        }

        if (principal.SubjectId != null && OctoObjectId.TryParse(principal.SubjectId, out var userRtId))
        {
            try
            {
                var repository = await call.Services.GetRequiredService<ISystemContext>()
                    .TryFindTenantRepositoryAsync(CallerTenantId(principal) ?? callTenantId).ConfigureAwait(false);
                if (repository != null)
                {
                    using var session = await repository.GetSessionAsync().ConfigureAwait(false);
                    session.StartTransaction();
                    var user = await repository.GetRtEntityByRtIdAsync<RtUser>(session, userRtId).ConfigureAwait(false);
                    await session.CommitTransactionAsync().ConfigureAwait(false);
                    if (!string.IsNullOrEmpty(user?.UserName))
                    {
                        return user.UserName;
                    }
                }
            }
            catch (Exception ex)
            {
                // The name is only for the audit record; a failed read never fails the call.
                call.Services.GetRequiredService<ILogger<IdentityMethodCall>>()
                    .LogDebug(ex, "The caller's user name could not be read for the audit record");
            }
        }

        call.Services.GetRequiredService<ILogger<IdentityMethodCall>>().LogWarning(
            "Cross-tenant grant audit: no user is stored for the caller's subject in its token tenant; the subject is recorded as the actor");
        return principal.Subject ?? "unknown";
    }

    /// <summary>A <c>METHOD_VALIDATION_FAILED</c> answer naming <paramref name="field" />.</summary>
    public static CkMethodFailure ValidationFailed(string field) =>
        new(CkMethodErrorCodes.MethodValidationFailed, new Dictionary<string, string> { ["field"] = field });
}
