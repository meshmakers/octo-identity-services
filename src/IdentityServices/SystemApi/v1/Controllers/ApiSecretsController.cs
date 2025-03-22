using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Contracts.ApiErrors;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ApiSecretsController : ControllerBase
{
    private readonly IDistributionEventHubService _distributionEventHubService;
    private readonly IOctoClientStore _octoClientStore;
    private readonly IOctoResourceStore _octoResourceStore;

    public ApiSecretsController(IOctoClientStore octoClientStore, IOctoResourceStore octoResourceStore,
        IDistributionEventHubService distributionEventHubService)
    {
        _octoClientStore = octoClientStore;
        _octoResourceStore = octoResourceStore;
        _distributionEventHubService = distributionEventHubService;
    }

    // GET system/v1/apiSecrets/client/xyz
    [HttpGet("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all secrets of the given client")]
    [ProducesResponseType(typeof(IEnumerable<ApiSecretDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetClient([Required] string clientId)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var client = await _octoClientStore.FindClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound();
        }

        return Ok(client.ClientSecrets.Select(CreateApiSecret));
    }

    // GET system/v1/apiSecrets/client/xyz/secretValue
    [HttpGet("client/{clientId}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns a secret of the given client")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetClientSecret([Required] string clientId, [Required] string secretValue)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var decodedSecretValue = secretValue.DecodeBase64();

        var client = await _octoClientStore.FindClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound(new NotFoundError($"Client '{clientId}' not found"));
        }

        var secret = client.ClientSecrets.FirstOrDefault(x => x.Value == decodedSecretValue);
        if (secret == null)
        {
            return NotFound(new NotFoundError($"API secret '{decodedSecretValue}' not found"));
        }

        return Ok(CreateApiSecret(secret));
    }

    // GET system/v1/apiSecrets/apiResource/xyz
    [HttpGet("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all secrets of the given API resource")]
    [ProducesResponseType(typeof(IEnumerable<ApiSecretDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetApiResource([Required] string apiResourceName)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var apiResources = await _octoResourceStore.FindApiResourcesByNameAsync(new[] { apiResourceName });
        var apiResource = apiResources.FirstOrDefault();
        if (apiResource == null)
        {
            return NotFound();
        }

        return Ok(apiResource.ApiSecrets.Select(CreateApiSecret));
    }

    // GET system/v1/apiSecrets/apiResource/xyz/secretValue
    [HttpGet("apiResource/{apiResourceName}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns a secret of the given API resource")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetApiResourceSecret([Required] string apiResourceName,
        [Required] string secretValue)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var decodedSecretValue = secretValue.DecodeBase64();

        var apiResources = await _octoResourceStore.FindApiResourcesByNameAsync(new[] { apiResourceName });
        var apiResource = apiResources.FirstOrDefault();
        if (apiResource == null)
        {
            return NotFound(new NotFoundError($"API resource '{apiResourceName}' not found"));
        }

        var secret = apiResource.ApiSecrets.FirstOrDefault(x => x.Value == decodedSecretValue);
        if (secret == null)
        {
            return NotFound(new NotFoundError($"API secret '{decodedSecretValue}' not found"));
        }

        return Ok(CreateApiSecret(secret));
    }

    // POST system/v1/apiSecrets/client/xyz
    [HttpPost("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new secret for a client")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> PostClient(
        [Required] [Description("ID of client to add secret")]
        string clientId,
        [Required] [FromBody] [Description("The secret data transfer object instance")]
        ApiSecretDto secretDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var client = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound();
        }

        secretDto.ValueClearText = Guid.NewGuid().ToString();
        secretDto.ValueEncrypted = secretDto.ValueClearText.Sha256();

        RtSecretRecord secret = new();
        ApplyToApiSecret(secret, secretDto);
        client.ClientSecrets.Add(secret);

        try
        {
            await _octoClientStore.UpdateAsync(clientId, client);
            await ClearCacheAsync();
            return Ok(secretDto);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // POST system/v1/apiSecrets/apiResource/xyz
    [HttpPost("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new secret for an API resource")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> PostApiResource(
        [Required] [Description("Name of API resource to add secret")]
        string apiResourceName,
        [Required] [FromBody] [Description("The secret data transfer object instance")]
        ApiSecretDto secretDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var apiResource = await _octoResourceStore.GetApiResourceByNameAsync(apiResourceName);
        if (apiResource == null)
        {
            return NotFound();
        }

        secretDto.ValueClearText = Guid.NewGuid().ToString();
        secretDto.ValueEncrypted = secretDto.ValueClearText.Sha256();

        RtSecretRecord secret = new();
        ApplyToApiSecret(secret, secretDto);
        apiResource.ApiSecrets.Add(secret);

        try
        {
            await _octoResourceStore.UpdateApiResourceAsync(apiResourceName, apiResource);
            await ClearCacheAsync();
            return Ok(secretDto);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // PUT system/v1/apiSecrets/apiResource/xyz
    [HttpPut("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates a secret")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> PutClient(
        [Required] [Description("ID of client")]
        string clientId,
        [Required] [FromBody] [Description("The secret data transfer object instance")]
        ApiSecretDto apiSecretDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var client = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound();
        }

        var secrets = client.ClientSecrets.Where(x => x.Value == apiSecretDto.ValueEncrypted).ToArray();
        if (!secrets.Any())
        {
            return NotFound(new NotFoundError($"Secret with value '{apiSecretDto.ValueEncrypted}' does not exist."));
        }

        var secret = secrets.First();
        ApplyToApiSecret(secret, apiSecretDto);

        try
        {
            await _octoClientStore.UpdateAsync(clientId, client);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
    }

    // PUT system/v1/apiSecrets/apiResource/xyz
    [HttpPut("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates a secret")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> PutApiResource(
        [Required] [Description("Name of the API resource")]
        string apiResourceName,
        [Required] [FromBody] [Description("The secret data transfer object instance")]
        ApiSecretDto apiSecretDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var apiResource = await _octoResourceStore.GetApiResourceByNameAsync(apiResourceName);
        if (apiResource == null)
        {
            return NotFound();
        }

        var secrets = apiResource.ApiSecrets.Where(x => x.Value == apiSecretDto.ValueEncrypted).ToArray();
        if (!secrets.Any())
        {
            return NotFound(new NotFoundError($"Secret with value '{apiSecretDto.ValueEncrypted}' does not exist."));
        }

        var secret = secrets.First();
        ApplyToApiSecret(secret, apiSecretDto);

        try
        {
            await _octoResourceStore.UpdateApiResourceAsync(apiResourceName, apiResource);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
    }


    // DELETE system/v1/apiSecrets/client/xyz/secretValue
    [HttpDelete("client/{clientId}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes a secret of a client")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> DeleteSecretOfClient(
        [Required] [Description("ID of the client")]
        string clientId,
        [Required] [Description("The sha256 value of the secret")]
        string secretValue)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var decodedSecretValue = secretValue.DecodeBase64();

        var octoClient = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (octoClient == null)
        {
            return NotFound(new NotFoundError($"Client with id '{clientId}' does not exist."));
        }

        var secrets = octoClient.ClientSecrets.Where(x => x.Value == decodedSecretValue).ToArray();
        if (!secrets.Any())
        {
            return NotFound(new NotFoundError($"Secret with value '{decodedSecretValue}' does not exist."));
        }

        foreach (var secret in secrets)
        {
            octoClient.ClientSecrets.Remove(secret);
        }

        try
        {
            await _octoClientStore.UpdateAsync(clientId, octoClient);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }


    // DELETE system/v1/apiSecrets/apiResource/xyz/secretValue
    [HttpDelete("apiResource/{apiResourceName}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes a secret of an API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> DeleteSecretOfApiResource(
        [Required] [Description("Name of the API resource")]
        string apiResourceName,
        [Required] [Description("The sha256 value of the secret")]
        string secretValue)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var decodedSecretValue = secretValue.DecodeBase64();

        var apiResource = await _octoResourceStore.GetApiResourceByNameAsync(apiResourceName);
        if (apiResource == null)
        {
            return NotFound();
        }

        var secrets = apiResource.ApiSecrets.Where(x => x.Value == decodedSecretValue).ToArray();
        if (!secrets.Any())
        {
            return NotFound(new NotFoundError($"Secret with value '{decodedSecretValue}' does not exist."));
        }

        foreach (var secret in secrets)
        {
            apiResource.ApiSecrets.Remove(secret);
        }

        try
        {
            await _octoResourceStore.UpdateApiResourceAsync(apiResourceName, apiResource);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    private Task ClearCacheAsync()
    {
        return _distributionEventHubService.PublishAsync(new CorsClientsUpdate(_octoResourceStore.TenantId,
            Guid.NewGuid(), DateTime.Now));
    }

    private ApiSecretDto CreateApiSecret(Secret secret)
    {
        var apiSecretDto = new ApiSecretDto
        {
            ExpirationDate = secret.Expiration,
            Description = secret.Description,
            ValueEncrypted = secret.Value
        };

        return apiSecretDto;
    }

    private void ApplyToApiSecret(RtSecretRecord secret, ApiSecretDto apiSecretDto)
    {
        secret.ExpirationDateTime = apiSecretDto.ExpirationDate;
        secret.Description = apiSecretDto.Description;
        secret.Value = apiSecretDto.ValueEncrypted;
    }
}