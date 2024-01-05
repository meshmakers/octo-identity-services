using System.ComponentModel.DataAnnotations;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Common.ApiErrors;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

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
    /// <summary>
    ///     Returns all secrets of the given client
    /// </summary>
    /// <returns></returns>
    [HttpGet("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    /// <summary>
    ///     Returns a secret of the given client
    /// </summary>
    /// <returns></returns>
    [HttpGet("client/{clientId}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    /// <summary>
    ///     Returns all secrets of the given API resource
    /// </summary>
    /// <returns></returns>
    [HttpGet("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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
    /// <summary>
    ///     Returns a secret of the given API resource
    /// </summary>
    /// <returns></returns>
    [HttpGet("apiResource/{apiResourceName}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IActionResult> GetApiResourceSecret([Required] string apiResourceName, [Required] string secretValue)
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

    /// <summary>
    ///     Creates new secret for client
    /// </summary>
    /// <param name="clientId">Id of client to add secret</param>
    /// <param name="secretDto">The secret data transfer object instance</param>
    /// <returns></returns>
    // POST system/v1/apiSecrets/client/xyz
    [HttpPost("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> PostClient([Required] string clientId, [Required] [FromBody] ApiSecretDto secretDto)
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

    /// <summary>
    ///     Creates new secret for an API resource
    /// </summary>
    /// <param name="apiResourceName">Name of API resource to add secret</param>
    /// <param name="secretDto">The secret data transfer object instance</param>
    /// <returns></returns>
    // POST system/v1/apiSecrets/apiResource/xyz
    [HttpPost("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> PostApiResource([Required] string apiResourceName, [Required] [FromBody] ApiSecretDto secretDto)
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
    /// <summary>
    ///     Updates a secret
    /// </summary>
    /// <param name="clientId">ID of client</param>
    /// <param name="apiSecretDto">The secret data transfer object instance</param>
    /// <returns></returns>
    [HttpPut("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> PutClient([Required] string clientId, [Required] [FromBody] ApiSecretDto apiSecretDto)
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
    /// <summary>
    ///     Updates a secret
    /// </summary>
    /// <param name="apiResourceName">Name of the API resource</param>
    /// <param name="apiSecretDto">The secret data transfer object instance</param>
    /// <returns></returns>
    [HttpPut("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> PutApiResource([Required] string apiResourceName, [Required] [FromBody] ApiSecretDto apiSecretDto)
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
    /// <summary>
    ///     Deletes a secret of given client
    /// </summary>
    /// <param name="clientId">Id of the client</param>
    /// <param name="secretValue">The sha256 value of the secret</param>
    /// <returns></returns>
    [HttpDelete("client/{clientId}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> DeleteSecretOfClient([Required] string clientId, [Required] string secretValue)
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
    /// <summary>
    ///     Deletes a secret of given api resource
    /// </summary>
    /// <param name="apiResourceName">Name of the API resource</param>
    /// <param name="secretValue">The sha256 value of the secret</param>
    /// <returns></returns>
    [HttpDelete("apiResource/{apiResourceName}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> DeleteSecretOfApiResource([Required] string apiResourceName, [Required] string secretValue)
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

    private Task ClearCacheAsync(string? tenantId = null)
    {
        return _distributionEventHubService.PublishAsync(new CorsClientsUpdate(tenantId));
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