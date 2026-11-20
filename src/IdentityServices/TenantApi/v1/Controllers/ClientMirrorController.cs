using System.ComponentModel;
using System.Text.Json;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.Runtime.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Meshmakers.Octo.Services.RestDeprecation;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// Manages <c>ClientCredentials</c> client mirrors — i.e. clients that have been
/// auto-provisioned from the calling (parent) tenant into one or more child tenants
/// because of the <c>AutoProvisionInChildTenants</c> flag. The actions that name a child tenant
/// (<c>provisionInTenant</c>, mirror secret rotation, mirror removal) only reach the caller's own tenant subtree
/// (<see cref="AdminProvisioningTargetScopeFilter"/>, again in the method handler and in the service).
/// Every write is a facade of a <c>Client.*Mirror*</c> method (docs/identity-rest-facades.md); the list stays a REST read.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/clients/{clientId}/mirrors")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ClientMirrorController : ControllerBase
{
    private readonly IOctoClientStore _clientStore;
    private readonly IClientMirrorProvisioningService _mirrorService;
    private readonly IIdentityMethodFacade _methodFacade;

    /// <param name="clientStore">Resolves the OAuth client id of the route to the method target</param>
    /// <param name="mirrorService">Lists the mirrors of a client (the read)</param>
    /// <param name="methodFacade">
    ///     Calls the mirror methods the write endpoints are facades of, in-process, outside any request transaction
    /// </param>
    public ClientMirrorController(
        IOctoClientStore clientStore,
        IClientMirrorProvisioningService mirrorService,
        IIdentityMethodFacade methodFacade)
    {
        _clientStore = clientStore;
        _mirrorService = mirrorService;
        _methodFacade = methodFacade;
    }

    // GET {tenantId}/v1/clients/{clientId}/mirrors
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Lists the sub-tenants this client has been auto-provisioned into")]
    [ProducesResponseType(typeof(IEnumerable<ClientMirrorDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get(
        [Required][Description("Client ID")] string clientId)
    {
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        }

        var mirrors = await _mirrorService.GetMirrorsAsync(_clientStore.TenantId, clientId);
        var dtos = mirrors.Select(m => new ClientMirrorDto(
            ParentClientId: m.ParentClientId,
            ParentTenantId: m.ParentTenantId,
            ChildTenantId: m.ChildTenantId,
            ProvisionedAt: m.ProvisionedAt,
            SecretHashVersion: m.SecretHashVersion));
        return Ok(dtos);
    }

    // POST {tenantId}/v1/clients/{clientId}/mirrors/provisionInExistingTenants
    /// <summary>Facade of the CK method <c>Client.ProvisionMirrors-1</c>.</summary>
    [HttpPost("provisionInExistingTenants")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.ClientMirrorMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Backfill: provisions this client into every existing sub-tenant of the caller. Idempotent.")]
    [ProducesResponseType(typeof(ClientMirrorBackfillResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ProvisionInExistingTenants(
        [Required][Description("Client ID")] string clientId)
    {
        var clientMissing = NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return clientMissing;
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientProvisionMirrorsMethodId, client.RtId.ToString(),
            new ClientProvisionMirrorsParameters(), User, HttpContext.RequestAborted);
        return response.ToActionResult(MirrorOptions(clientId, clientMissing)
            .MapSuccess(result =>
            {
                var record = Deserialize<RtClientMirrorBackfillResultRecord>(result.ResultJson);
                return Ok(new ClientMirrorBackfillResponseDto(record.ChildTenantsConsidered, record.NewlyProvisioned,
                    record.AlreadyPresent));
            })
            .MapError(ClientMirrorMethodErrors.BackfillNotStarted, _ => BadRequest(new OperationFailedErrorDto(
                $"Backfill could not be started for client '{clientId}'."))));
    }

    // POST {tenantId}/v1/clients/{clientId}/mirrors/provisionInTenant?childTenantId=…
    /// <summary>Facade of the CK method <c>Client.ProvisionMirrorInTenant-1</c>.</summary>
    [HttpPost("provisionInTenant")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.ClientMirrorMethodsLink)]
    [TypeFilter(typeof(AdminProvisioningTargetScopeFilter))]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Provisions this client into a single named sub-tenant. Idempotent.")]
    [ProducesResponseType(typeof(ClientMirrorProvisionResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ProvisionInTenant(
        [Required][Description("Client ID")] string clientId,
        [Required][FromQuery][Description("ID of the child tenant to provision into")] string childTenantId)
    {
        var clientMissing = NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return clientMissing;
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId, client.RtId.ToString(),
            new ClientProvisionMirrorInTenantParameters { ChildTenantId = childTenantId }, User,
            HttpContext.RequestAborted);
        return response.ToActionResult(MirrorOptions(clientId, clientMissing)
            .MapSuccess(result =>
            {
                var record = Deserialize<RtClientMirrorProvisionResultRecord>(result.ResultJson);
                return Ok(new ClientMirrorProvisionResponseDto(record.FlaggedClientsConsidered, record.NewlyProvisioned,
                    record.AlreadyPresent));
            }));
    }

    // POST {tenantId}/v1/clients/{clientId}/mirrors/{childTenantId}/secret
    /// <summary>
    ///     Issues a fresh, tenant-specific secret for one mirror and returns it <b>once</b>. Facade of the CK method
    ///     <c>Client.RotateMirrorSecret-1</c>.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         This is how the holder of a mirrored client learns its own, per-tenant credential.
    ///         Mirroring copies the parent's secret into every child tenant, so that credential
    ///         alone is valid instance-wide and proves nothing about which tenant the caller belongs
    ///         to; a secret issued here proves exactly one tenant.
    ///     </para>
    ///     <para>
    ///         🔴 The value is <b>not recoverable</b> — only its SHA-256 hash is stored. Capture it
    ///         from this response; calling again issues a new secret and invalidates the previous
    ///         one. It is never written to a log, an audit record or a trace.
    ///     </para>
    ///     <para>
    ///         ⚠️ The mirror also keeps accepting the inherited parent secret until the migration
    ///         step that removes it; until then the instance-wide credential is still live.
    ///     </para>
    /// </remarks>
    [HttpPost("{childTenantId}/secret")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.ClientMirrorMethodsLink)]
    [TypeFilter(typeof(AdminProvisioningTargetScopeFilter))]
    // Issuing (rotating) a mirror's secret is an API secret write -> SecretManagement (staged).
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
    [EndpointSummary("Issues a fresh tenant-specific secret for this mirror and returns it once.")]
    [ProducesResponseType(typeof(MirrorSecretResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RotateSecret(
        [Required][Description("Client ID")] string clientId,
        [Required][Description("Sub-tenant whose mirror gets the new secret")] string childTenantId)
    {
        var mirrorMissing = MirrorNotFound(clientId, childTenantId);
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return mirrorMissing;
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientRotateMirrorSecretMethodId, client.RtId.ToString(),
            new ClientRotateMirrorSecretParameters { ChildTenantId = childTenantId }, User, HttpContext.RequestAborted);
        return response.ToActionResult(MirrorOptions(clientId, mirrorMissing)
            .MapSuccess(result =>
            {
                // The clear text is read from the in-process envelope only to build the one-time body; never logged.
                var secret = result.ResultJson == null ? null : JsonSerializer.Deserialize<string>(result.ResultJson);
                return string.IsNullOrEmpty(secret)
                    ? BadRequest(new InternalServerErrorDto("Issuing the mirror secret failed."))
                    : Ok(new MirrorSecretResponseDto(clientId, childTenantId, secret));
            })
            .MapError(ClientMirrorMethodErrors.MirrorNotFound, _ => mirrorMissing)
            .MapError(ClientMirrorMethodErrors.ClientSecretNotRequired, _ => BadRequest(new OperationFailedErrorDto(
                $"Client '{clientId}' is a public client — it has no secret, so there is no "
                + "per-tenant secret to issue for its mirrors."))));
    }

    // DELETE {tenantId}/v1/clients/{clientId}/mirrors/{childTenantId}
    /// <summary>Facade of the CK method <c>Client.RemoveMirror-1</c>.</summary>
    [HttpDelete("{childTenantId}")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.ClientMirrorMethodsLink)]
    [TypeFilter(typeof(AdminProvisioningTargetScopeFilter))]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Manually removes the mirror of this client in a single sub-tenant.")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(
        [Required][Description("Client ID")] string clientId,
        [Required][Description("Sub-tenant ID to remove the mirror from")] string childTenantId)
    {
        var mirrorMissing = MirrorNotFound(clientId, childTenantId);
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return mirrorMissing;
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientRemoveMirrorMethodId, client.RtId.ToString(),
            new ClientRemoveMirrorParameters { ChildTenantId = childTenantId }, User, HttpContext.RequestAborted);
        return response.ToActionResult(MirrorOptions(clientId, mirrorMissing)
            .MapSuccess(_ => NoContent())
            .MapError(ClientMirrorMethodErrors.MirrorNotFound, _ => mirrorMissing));
    }

    private NotFoundObjectResult MirrorNotFound(string clientId, string childTenantId) =>
        NotFound(new NotFoundErrorDto($"No mirror tracked for client '{clientId}' in child tenant '{childTenantId}'."));

    /// <summary>
    ///     The mappings the mirror writes share: the client gone (or not readable) <paramref name="targetMissing" />, a child
    ///     tenant outside the caller's or the parent's subtree the empty <c>403</c> of the scope filter, a client without the
    ///     flag <c>400</c> with the earlier message. Other refusals keep the default <c>403</c> problem, a handler failure the
    ///     default <c>500</c> problem (no exception text leaves the service).
    /// </summary>
    private CkMethodFacadeOptions MirrorOptions(string clientId, IActionResult targetMissing) =>
        new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => targetMissing)
            .MapError(CkMethodErrorCodes.MethodForbidden, error =>
                error.Parameters.GetValueOrDefault("reason") == CrossTenantMethodSupport.TenantOutOfScopeReason
                    ? new ForbidResult()
                    : CkMethodFacadeResults.Problem(error, StatusCodes.Status403Forbidden))
            .MapError(ClientMirrorMethodErrors.AutoProvisionDisabled, _ => BadRequest(new OperationFailedErrorDto(
                $"Client '{clientId}' is not flagged AutoProvisionInChildTenants. Set the flag first.")));

    internal static T Deserialize<T>(string? resultJson) where T : class =>
        (resultJson == null ? null : JsonSerializer.Deserialize<T>(resultJson, CkMethodJson.Options))
        ?? throw new InvalidOperationException($"The method answered without a {typeof(T).Name}.");
}

/// <summary>
///     One-time response of the mirror-secret rotation endpoint.
/// </summary>
/// <param name="ClientId">The mirrored client id — unchanged by rotation.</param>
/// <param name="ChildTenantId">The tenant this secret is valid for, and only this one.</param>
/// <param name="Secret">
///     The new secret in plaintext. 🔴 Returned once and unrecoverable afterwards, because only its
///     SHA-256 hash is stored. Defined in this repository rather than in the shared contracts
///     package on purpose: nothing but the issuing endpoint should ever be able to name this shape,
///     and no client library should offer a "read the mirror secret" call, since no such read
///     exists.
/// </param>
public sealed record MirrorSecretResponseDto(string ClientId, string ChildTenantId, string Secret)
{
    /// <summary>Keeps the secret out of accidental interpolation, log lines and exception text.</summary>
    public override string ToString() =>
        $"{nameof(MirrorSecretResponseDto)} {{ ClientId = {ClientId}, ChildTenantId = {ChildTenantId} }}";
}

/// <summary>
/// Sub-resource on the existing clients route to flip <c>AutoProvisionInChildTenants</c>
/// without requiring callers to PUT the full client object back. Facade of the CK method
/// <c>Client.SetMirrorAutoProvision-1</c>.
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/clients/{clientId}/autoProvisionInChildTenants")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ClientAutoProvisionFlagController : ControllerBase
{
    private readonly IOctoClientStore _clientStore;
    private readonly IIdentityMethodFacade _methodFacade;

    /// <param name="clientStore">Resolves the OAuth client id of the route to the method target</param>
    /// <param name="methodFacade">Calls <c>Client.SetMirrorAutoProvision-1</c> in-process, outside any request transaction</param>
    public ClientAutoProvisionFlagController(IOctoClientStore clientStore, IIdentityMethodFacade methodFacade)
    {
        _clientStore = clientStore;
        _methodFacade = methodFacade;
    }

    // PATCH {tenantId}/v1/clients/{clientId}/autoProvisionInChildTenants
    [HttpPatch]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.ClientMirrorMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Sets the AutoProvisionInChildTenants flag on a client without rewriting the full client.")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Set(
        [Required][Description("Client ID")] string clientId,
        [Required][FromBody] SetAutoProvisionInChildTenantsDto body)
    {
        // The method is a version-checked read-modify-write and the store's post-commit hook propagates the new state to
        // mirrors when applicable. Flipping the flag from true → false leaves existing mirrors in place; the operator
        // removes them explicitly via DELETE mirrors/{childTenantId} or by deleting the parent client.
        var clientMissing = NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return clientMissing;
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientSetMirrorAutoProvisionMethodId, client.RtId.ToString(),
            new ClientSetMirrorAutoProvisionParameters { Enabled = body.Enabled }, User, HttpContext.RequestAborted);
        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapSuccess(_ => NoContent())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => clientMissing)
            .MapError(ClientMirrorMethodErrors.ConcurrentChange, _ => Problem(
                detail: "The client was changed concurrently by other requests. Please retry.",
                statusCode: StatusCodes.Status409Conflict)));
    }
}
