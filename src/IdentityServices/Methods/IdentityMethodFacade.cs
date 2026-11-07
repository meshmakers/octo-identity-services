using System.Security.Claims;
using System.Text.Json;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;

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
}

internal sealed class IdentityMethodFacade(
    ICkMethodDispatcher dispatcher,
    ICkMethodTimeoutResolver timeouts,
    IMultiTenancyResolverService tenantResolver) : IIdentityMethodFacade
{
    /// <summary>CK type id of the identity user (the declaring type of the <c>User.*</c> methods).</summary>
    public const string UserCkTypeId = "System.Identity/User";

    public async Task<CkMethodResponse> InvokeAsync<TParameters>(string ckTypeId, string methodId, string? targetRtId,
        TParameters parameters, ClaimsPrincipal user, CancellationToken cancellationToken) where TParameters : class
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

        using (CkMethodPrincipalScope.Begin(CkMethodPrincipal.FromClaimsPrincipal(user)))
        {
            return await dispatcher.InvokeAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}
