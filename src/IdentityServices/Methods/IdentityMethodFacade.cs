using System.Security.Claims;
using System.Text.Json;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     The REST facades of the identity service call the <c>System.Identity</c> methods they serve through this helper
///     (AB#8412): it builds the <see cref="CkMethodRequest" /> for the tenant of the HTTP request, makes the authenticated
///     HTTP user the method caller (<see cref="CkMethodPrincipalScope" />) and calls the method through
///     <see cref="ICkMethodDispatcher" />. The identity service hosts the handlers, so the call runs in this process (AB#8411):
///     declared authorization, parameter validation, redaction, audit and metrics as for a GraphQL call, nothing on the bus.
/// </summary>
public interface IIdentityMethodFacade
{
    /// <summary>
    ///     Calls <paramref name="methodId" /> on the entity <paramref name="targetRtId" /> of <paramref name="ckTypeId" /> with
    ///     <paramref name="parameters" /> as the caller <paramref name="user" />; <paramref name="targetRtId" /> is <c>null</c>
    ///     for a static method (<c>User.CreateUser</c>, AB#8413). Never throws for a failing call; the failure is the returned
    ///     envelope.
    /// </summary>
    Task<CkMethodResponse> InvokeAsync<TParameters>(string ckTypeId, string methodId, string? targetRtId,
        TParameters parameters, ClaimsPrincipal user, CancellationToken cancellationToken) where TParameters : class;

    /// <summary>
    ///     Calls the <c>allowSelf</c> instance method <paramref name="methodId" /> of <c>System.Identity/User</c> on the user
    ///     <paramref name="userRtId" /> for the account pages (AB#8414: <c>api/manage/change-password</c>,
    ///     <c>set-password</c>). <paramref name="accountUser" /> is the principal of the identity session cookie
    ///     (<c>Identity.Application</c>); it carries no OAuth scope, so the facade builds the method caller itself:
    ///     subject = the cookie's user id, <b>no role</b>, scope <c>octo_api</c> only. With no role the declared authorization
    ///     can only pass through <c>allowSelf</c> on the caller's own user, so the cookie never reaches an administrator path
    ///     or another user, and nothing a bearer token may do changes (a bearer token never reaches the account endpoints:
    ///     their default scheme is the cookie). A principal that is not the session cookie, or whose user id is not
    ///     <paramref name="userRtId" />, gets <c>METHOD_FORBIDDEN</c> without a call.
    /// </summary>
    Task<CkMethodResponse> InvokeForAccountOwnerAsync<TParameters>(string methodId, string userRtId,
        TParameters parameters, ClaimsPrincipal accountUser, CancellationToken cancellationToken) where TParameters : class;
}

internal sealed class IdentityMethodFacade(
    ICkMethodDispatcher dispatcher,
    ICkMethodTimeoutResolver timeouts,
    IMultiTenancyResolverService tenantResolver,
    IOptions<IdentityOptions> identityOptions) : IIdentityMethodFacade
{
    /// <summary>CK type id of the identity user (the declaring type of the <c>User.*</c> methods).</summary>
    public const string UserCkTypeId = "System.Identity/User";

    public Task<CkMethodResponse> InvokeAsync<TParameters>(string ckTypeId, string methodId, string? targetRtId,
        TParameters parameters, ClaimsPrincipal user, CancellationToken cancellationToken) where TParameters : class =>
        DispatchAsync(ckTypeId, methodId, targetRtId, parameters, CkMethodPrincipal.FromClaimsPrincipal(user),
            cancellationToken);

    public Task<CkMethodResponse> InvokeForAccountOwnerAsync<TParameters>(string methodId, string userRtId,
        TParameters parameters, ClaimsPrincipal accountUser, CancellationToken cancellationToken) where TParameters : class
    {
        var cookieUserId = accountUser.FindFirst(identityOptions.Value.ClaimsIdentity.UserIdClaimType)?.Value;
        var isSessionCookie = accountUser.Identities.Any(i =>
            i.IsAuthenticated && string.Equals(i.AuthenticationType, IdentityConstants.ApplicationScheme, StringComparison.Ordinal));
        if (!isSessionCookie || string.IsNullOrWhiteSpace(userRtId) ||
            !string.Equals(cookieUserId, userRtId, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(CkMethodResponse.Failed(Guid.NewGuid(), IdentityMethodHost.ServiceName,
                CkMethodAuthorizationErrors.Forbidden(methodId)));
        }

        // Subject only, no role, the base API scope only: the declaration can admit this caller through allowSelf alone.
        var caller = new CkMethodPrincipal(userRtId, [], [CkMethodAuthorizationOptions.ApiScope]);
        return DispatchAsync(UserCkTypeId, methodId, userRtId, parameters, caller, cancellationToken);
    }

    private async Task<CkMethodResponse> DispatchAsync<TParameters>(string ckTypeId, string methodId, string? targetRtId,
        TParameters parameters, CkMethodPrincipal caller, CancellationToken cancellationToken) where TParameters : class
    {
        var tenantId = tenantResolver.GetTenantId();
        var request = new CkMethodRequest(tenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, CkMethodJson.Options),
            DeadlineUtc = timeouts.GetDeadlineUtc(tenantId, ckTypeId, methodId)
        };

        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await dispatcher.InvokeAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}
