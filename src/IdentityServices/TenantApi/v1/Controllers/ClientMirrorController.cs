using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// Manages <c>ClientCredentials</c> client mirrors — i.e. clients that have been
/// auto-provisioned from the calling (parent) tenant into one or more child tenants
/// because of the <c>AutoProvisionInChildTenants</c> flag.
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/clients/{clientId}/mirrors")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ClientMirrorController : ControllerBase
{
    private readonly IOctoClientStore _clientStore;
    private readonly IClientMirrorProvisioningService _mirrorService;

    public ClientMirrorController(
        IOctoClientStore clientStore,
        IClientMirrorProvisioningService mirrorService)
    {
        _clientStore = clientStore;
        _mirrorService = mirrorService;
    }

    // GET {tenantId}/v1/clients/{clientId}/mirrors
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    [HttpPost("provisionInExistingTenants")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Backfill: provisions this client into every existing sub-tenant of the caller. Idempotent.")]
    [ProducesResponseType(typeof(ClientMirrorBackfillResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ProvisionInExistingTenants(
        [Required][Description("Client ID")] string clientId)
    {
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        }

        if (!client.AutoProvisionInChildTenants)
        {
            return BadRequest(new OperationFailedErrorDto(
                $"Client '{clientId}' is not flagged AutoProvisionInChildTenants. Set the flag first."));
        }

        var result = await _mirrorService.ProvisionForAllChildTenantsAsync(
            _clientStore.TenantId, clientId);

        // The service returns null when the client either doesn't exist or isn't flagged —
        // both already short-circuited above, so this shouldn't happen. Defensive:
        if (result == null)
        {
            return BadRequest(new OperationFailedErrorDto(
                $"Backfill could not be started for client '{clientId}'."));
        }

        return Ok(new ClientMirrorBackfillResponseDto(
            result.ChildTenantsConsidered,
            result.NewlyProvisioned,
            result.AlreadyPresent));
    }

    // POST {tenantId}/v1/clients/{clientId}/mirrors/provisionInTenant?childTenantId=…
    [HttpPost("provisionInTenant")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Provisions this client into a single named sub-tenant. Idempotent.")]
    [ProducesResponseType(typeof(ClientMirrorProvisionResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(OperationFailedErrorDto), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ProvisionInTenant(
        [Required][Description("Client ID")] string clientId,
        [Required][FromQuery][Description("ID of the child tenant to provision into")] string childTenantId)
    {
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        }

        if (!client.AutoProvisionInChildTenants)
        {
            return BadRequest(new OperationFailedErrorDto(
                $"Client '{clientId}' is not flagged AutoProvisionInChildTenants. Set the flag first."));
        }

        var result = await _mirrorService.ProvisionInTenantAsync(
            _clientStore.TenantId, clientId, childTenantId);

        return Ok(new ClientMirrorProvisionResponseDto(
            result.FlaggedClientsConsidered,
            result.NewlyProvisioned,
            result.AlreadyPresent));
    }

    // DELETE {tenantId}/v1/clients/{clientId}/mirrors/{childTenantId}
    [HttpDelete("{childTenantId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Manually removes the mirror of this client in a single sub-tenant.")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(
        [Required][Description("Client ID")] string clientId,
        [Required][Description("Sub-tenant ID to remove the mirror from")] string childTenantId)
    {
        var removed = await _mirrorService.RemoveMirrorAsync(
            _clientStore.TenantId, clientId, childTenantId);

        if (!removed)
        {
            return NotFound(new NotFoundErrorDto(
                $"No mirror tracked for client '{clientId}' in child tenant '{childTenantId}'."));
        }

        return NoContent();
    }
}

/// <summary>
/// Sub-resource on the existing clients route to flip <c>AutoProvisionInChildTenants</c>
/// without requiring callers to PUT the full client object back.
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/clients/{clientId}/autoProvisionInChildTenants")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ClientAutoProvisionFlagController : ControllerBase
{
    private readonly IOctoClientStore _clientStore;

    public ClientAutoProvisionFlagController(IOctoClientStore clientStore)
    {
        _clientStore = clientStore;
    }

    // PATCH {tenantId}/v1/clients/{clientId}/autoProvisionInChildTenants
    [HttpPatch]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Sets the AutoProvisionInChildTenants flag on a client without rewriting the full client.")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Set(
        [Required][Description("Client ID")] string clientId,
        [Required][FromBody] SetAutoProvisionInChildTenantsDto body)
    {
        var client = await _clientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        }

        client.AutoProvisionInChildTenants = body.Enabled;

        // UpdateAsync's post-commit hook (#4044) propagates the new state to mirrors when
        // applicable. Flipping the flag from true → false leaves existing mirrors in place;
        // the operator removes them explicitly via DELETE mirrors/{childTenantId} or by
        // deleting the parent client.
        await _clientStore.UpdateAsync(clientId, client);
        return NoContent();
    }
}
