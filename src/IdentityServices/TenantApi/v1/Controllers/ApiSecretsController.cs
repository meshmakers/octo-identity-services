using System.Buffers.Text;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.Authentication;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
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
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all secrets of the given client")]
    [ProducesResponseType(typeof(IEnumerable<ApiSecretDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetClient([Required] string clientId)
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

        return Ok(client.ClientSecrets.Select(CreateApiSecret));
    }

    // GET system/v1/apiSecrets/client/xyz/secretValue
    [HttpGet("client/{clientId}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns a secret of the given client")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetClientSecret([Required] string clientId, [Required] string secretValue)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var decodedSecretValue = secretValue.DecodeBase64();

        var client = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client '{clientId}' not found"));
        }

        var secret = client.ClientSecrets.FirstOrDefault(x => x.Value == decodedSecretValue);
        if (secret == null)
        {
            return NotFound(new NotFoundErrorDto(SecretNotFoundMessage));
        }

        return Ok(CreateApiSecret(secret));
    }

    // GET system/v1/apiSecrets/apiResource/xyz
    [HttpGet("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all secrets of the given API resource")]
    [ProducesResponseType(typeof(IEnumerable<ApiSecretDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetApiResource([Required] string apiResourceName)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var apiResources = await _octoResourceStore.FindRtApiResourcesByNameAsync(new[] { apiResourceName });
        var apiResource = apiResources.FirstOrDefault();
        if (apiResource == null)
        {
            return NotFound();
        }

        return Ok(apiResource.ApiSecrets.Select(CreateApiSecret));
    }

    // GET system/v1/apiSecrets/apiResource/xyz/secretValue
    [HttpGet("apiResource/{apiResourceName}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
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

        var apiResources = await _octoResourceStore.FindRtApiResourcesByNameAsync(new[] { apiResourceName });
        var apiResource = apiResources.FirstOrDefault();
        if (apiResource == null)
        {
            return NotFound(new NotFoundErrorDto($"API resource '{apiResourceName}' not found"));
        }

        var secret = apiResource.ApiSecrets.FirstOrDefault(x => x.Value == decodedSecretValue);
        if (secret == null)
        {
            return NotFound(new NotFoundErrorDto(SecretNotFoundMessage));
        }

        return Ok(CreateApiSecret(secret));
    }

    // POST system/v1/apiSecrets/client/xyz
    [HttpPost("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a new secret for a client")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> PostClient(
        [Required] [Description("ID of client to add secret")]
        string clientId,
        [Required] [FromBody] [Description("Expiration date and description of the new secret")]
        CreateApiSecretRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var secretDto = GenerateSecret(request);

        try
        {
            var client = await _octoClientStore.MutateAsync(clientId, current =>
            {
                RtSecretRecord secret = new();
                ApplyToApiSecret(secret, secretDto);
                current.ClientSecrets.Add(secret);
                return true;
            });
            if (client == null)
            {
                return NotFound();
            }

            await ClearCacheAsync();
            return Ok(secretDto);
        }
        catch (RtVersionConflictException)
        {
            return Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }
    }

    // POST system/v1/apiSecrets/apiResource/xyz
    [HttpPost("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a new secret for an API resource")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> PostApiResource(
        [Required] [Description("Name of API resource to add secret")]
        string apiResourceName,
        [Required] [FromBody] [Description("Expiration date and description of the new secret")]
        CreateApiSecretRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var secretDto = GenerateSecret(request);

        try
        {
            var apiResource = await _octoResourceStore.MutateApiResourceAsync(apiResourceName, current =>
            {
                RtSecretRecord secret = new();
                ApplyToApiSecret(secret, secretDto);
                current.ApiSecrets.Add(secret);
                return true;
            });
            if (apiResource == null)
            {
                return NotFound();
            }

            await ClearCacheAsync();
            return Ok(secretDto);
        }
        catch (RtVersionConflictException)
        {
            return Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }
    }

    // PUT system/v1/apiSecrets/apiResource/xyz
    [HttpPut("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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

        if (string.IsNullOrWhiteSpace(apiSecretDto.ValueEncrypted))
        {
            ModelState.AddModelError(nameof(ApiSecretDto.ValueEncrypted), ValueEncryptedRequiredMessage);
            return BadRequest(ModelState);
        }

        try
        {
            var replaced = false;
            var client = await _octoClientStore.MutateAsync(clientId,
                current => replaced = ReplaceSecret(current.ClientSecrets, apiSecretDto));
            if (client == null)
            {
                return NotFound();
            }

            if (!replaced)
            {
                return NotFound(new NotFoundErrorDto(SecretNotFoundMessage));
            }

            await ClearCacheAsync();
        }
        catch (RtVersionConflictException)
        {
            return Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }

        return Ok();
    }

    // PUT system/v1/apiSecrets/apiResource/xyz
    [HttpPut("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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

        if (string.IsNullOrWhiteSpace(apiSecretDto.ValueEncrypted))
        {
            ModelState.AddModelError(nameof(ApiSecretDto.ValueEncrypted), ValueEncryptedRequiredMessage);
            return BadRequest(ModelState);
        }

        try
        {
            var replaced = false;
            var apiResource = await _octoResourceStore.MutateApiResourceAsync(apiResourceName,
                current => replaced = ReplaceSecret(current.ApiSecrets, apiSecretDto));
            if (apiResource == null)
            {
                return NotFound();
            }

            if (!replaced)
            {
                return NotFound(new NotFoundErrorDto(SecretNotFoundMessage));
            }

            await ClearCacheAsync();
        }
        catch (RtVersionConflictException)
        {
            return Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }

        return Ok();
    }


    // DELETE system/v1/apiSecrets/client/xyz/secretValue
    [HttpDelete("client/{clientId}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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

        try
        {
            // RemoveAll with a predicate (AB#7989): the list of an entity read from the database hands out new
            // wrapper instances of the stored records, so Remove(wrapper) found nothing and the secret stayed.
            // The write is version-checked, so a concurrent secret write cannot bring the removed secret back.
            var removed = 0;
            var octoClient = await _octoClientStore.MutateAsync(clientId,
                current => (removed = current.ClientSecrets.RemoveAll(x => x.Value == decodedSecretValue)) > 0);
            if (octoClient == null)
            {
                return NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
            }

            if (removed == 0)
            {
                return NotFound(new NotFoundErrorDto(SecretNotFoundMessage));
            }

            await ClearCacheAsync();
            return Ok();
        }
        catch (RtVersionConflictException)
        {
            return Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }
    }


    // DELETE system/v1/apiSecrets/apiResource/xyz/secretValue
    [HttpDelete("apiResource/{apiResourceName}/{secretValue}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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

        try
        {
            // RemoveAll with a predicate and a version-checked write (AB#7989), see DeleteSecretOfClient.
            var removed = 0;
            var apiResource = await _octoResourceStore.MutateApiResourceAsync(apiResourceName,
                current => (removed = current.ApiSecrets.RemoveAll(x => x.Value == decodedSecretValue)) > 0);
            if (apiResource == null)
            {
                return NotFound();
            }

            if (removed == 0)
            {
                return NotFound(new NotFoundErrorDto(SecretNotFoundMessage));
            }

            await ClearCacheAsync();
            return Ok();
        }
        catch (RtVersionConflictException)
        {
            return Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict);
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }
    }

    // The 404 answer never echoes the secret value (the stored hash) the caller sent (AB#7989).
    private const string SecretNotFoundMessage = "The secret does not exist.";

    // Every secret write is a version-checked read-modify-write (AB#7989); after repeated concurrent changes it gives up.
    private const string ConcurrentChangeMessage =
        "The secrets were changed concurrently by another request. Please retry.";

    private const string ValueEncryptedRequiredMessage =
        "ValueEncrypted is required to identify the secret to update.";

    /// <summary>
    ///     Generates a new secret: 32 bytes (256 bit) from the CSPRNG, URL-safe Base64 without padding. The
    ///     returned DTO carries the clear text (shown once) and the stored hash; nothing of it is logged.
    /// </summary>
    private static ApiSecretDto GenerateSecret(CreateApiSecretRequestDto request)
    {
        var clearText = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        return new ApiSecretDto
        {
            ValueClearText = clearText,
            ValueEncrypted = OctoSecretHasher.HashSecret(clearText),
            ExpirationDate = request.ExpirationDate,
            Description = request.Description
        };
    }

    // The records handed out by the secret list are snapshots: changing one in place is not written back
    // with the entity, so the updated record replaces the old one in the list. Returns false when no secret
    // has the value of the update.
    private static bool ReplaceSecret(IList<RtSecretRecord> secrets, ApiSecretDto update)
    {
        for (var i = 0; i < secrets.Count; i++)
        {
            if (secrets[i].Value == update.ValueEncrypted)
            {
                RtSecretRecord replacement = new();
                ApplyToApiSecret(replacement, update);
                secrets[i] = replacement;
                return true;
            }
        }

        return false;
    }

    private Task ClearCacheAsync()
    {
        return _distributionEventHubService.PublishAsync(new CorsClientsUpdate(_octoResourceStore.TenantId,
            Guid.NewGuid(), DateTime.Now));
    }

    private static ApiSecretDto CreateApiSecret(RtSecretRecord secret)
    {
        var apiSecretDto = new ApiSecretDto
        {
            ExpirationDate = secret.ExpirationDateTime,
            Description = secret.Description,
            ValueEncrypted = secret.Value ?? string.Empty
        };

        return apiSecretDto;
    }

    private static void ApplyToApiSecret(RtSecretRecord secret, ApiSecretDto apiSecretDto)
    {
        secret.ExpirationDateTime = apiSecretDto.ExpirationDate;
        secret.Description = apiSecretDto.Description;
        secret.Value = apiSecretDto.ValueEncrypted;
    }
}