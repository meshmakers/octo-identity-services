using System.Buffers.Text;
using System.Diagnostics;
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
using Meshmakers.Octo.Backend.IdentityServices.Logging;

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
    private readonly ILogger<ApiSecretsController> _logger;

    public ApiSecretsController(IOctoClientStore octoClientStore, IOctoResourceStore octoResourceStore,
        IDistributionEventHubService distributionEventHubService, ILogger<ApiSecretsController> logger)
    {
        _octoClientStore = octoClientStore;
        _octoResourceStore = octoResourceStore;
        _distributionEventHubService = distributionEventHubService;
        _logger = logger;
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

    // POST {tenant}/v1/apiSecrets/client/xyz/lookup   body: { "valueEncrypted": "<stored hash>" }
    /// <summary>
    ///     Returns one secret of a client, named by its stored value in the body (AB#8008).
    /// </summary>
    [HttpPost("client/{clientId}/" + LookupAction)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns a secret of the given client (stored value in the body)")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> LookupClientSecret([Required] string clientId,
        [Required] [FromBody] ApiSecretValueRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        return await GetClientSecretCoreAsync(clientId, request.ValueEncrypted);
    }

    // GET {tenant}/v1/apiSecrets/client/xyz/{base64(stored hash)}
    /// <summary>
    ///     Deprecated (AB#8008): the stored value travels in the URL path. Kept for one release for older octo-cli/SDK
    ///     clients; use <c>POST apiSecrets/client/{clientId}/lookup</c>.
    /// </summary>
    [HttpGet("client/{clientId}/{" + LegacySecretRouteValue + "}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Deprecated: returns a secret of the given client (stored value in the path)")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetClientSecret([Required] string clientId)
    {
        // The value is read from the route here, not bound as an action argument: ASP.NET Core writes the action
        // arguments into its TRACE log.
        var value = TakeLegacySecretValue("GetClientSecret", "client", clientId);
        if (value == null)
        {
            return BadRequest();
        }

        return await GetClientSecretCoreAsync(clientId, value);
    }

    private async Task<IActionResult> GetClientSecretCoreAsync(string clientId, string storedValue)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client '{clientId}' not found"));
        }

        var secret = client.ClientSecrets.FirstOrDefault(x => x.Value == storedValue);
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

    // POST {tenant}/v1/apiSecrets/apiResource/xyz/lookup   body: { "valueEncrypted": "<stored hash>" }
    /// <summary>
    ///     Returns one secret of an API resource, named by its stored value in the body (AB#8008).
    /// </summary>
    [HttpPost("apiResource/{apiResourceName}/" + LookupAction)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns a secret of the given API resource (stored value in the body)")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> LookupApiResourceSecret([Required] string apiResourceName,
        [Required] [FromBody] ApiSecretValueRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        return await GetApiResourceSecretCoreAsync(apiResourceName, request.ValueEncrypted);
    }

    // GET {tenant}/v1/apiSecrets/apiResource/xyz/{base64(stored hash)}
    /// <summary>
    ///     Deprecated (AB#8008): the stored value travels in the URL path. Kept for one release for older octo-cli/SDK
    ///     clients; use <c>POST apiSecrets/apiResource/{apiResourceName}/lookup</c>.
    /// </summary>
    [HttpGet("apiResource/{apiResourceName}/{" + LegacySecretRouteValue + "}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Deprecated: returns a secret of the given API resource (stored value in the path)")]
    [ProducesResponseType(typeof(ApiSecretDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetApiResourceSecret([Required] string apiResourceName)
    {
        var value = TakeLegacySecretValue("GetApiResourceSecret", "apiResource", apiResourceName);
        if (value == null)
        {
            return BadRequest();
        }

        return await GetApiResourceSecretCoreAsync(apiResourceName, value);
    }

    private async Task<IActionResult> GetApiResourceSecretCoreAsync(string apiResourceName, string storedValue)
    {
        var apiResources = await _octoResourceStore.FindRtApiResourcesByNameAsync(new[] { apiResourceName });
        var apiResource = apiResources.FirstOrDefault();
        if (apiResource == null)
        {
            return NotFound(new NotFoundErrorDto($"API resource '{apiResourceName}' not found"));
        }

        var secret = apiResource.ApiSecrets.FirstOrDefault(x => x.Value == storedValue);
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


    // POST {tenant}/v1/apiSecrets/client/xyz/delete   body: { "valueEncrypted": "<stored hash>" }
    /// <summary>
    ///     Deletes one secret of a client, named by its stored value in the body (AB#8008). A POST sub-resource, not a
    ///     DELETE with a body: a DELETE body has no defined semantics (RFC 9110) and proxies and client libraries may drop
    ///     it; the API already uses POST sub-resources for actions (<c>users/{userName}/revokeSessions</c>).
    /// </summary>
    [HttpPost("client/{clientId}/" + DeleteAction)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Deletes a secret of a client (stored value in the body)")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteClientSecret(
        [Required] [Description("ID of the client")]
        string clientId,
        [Required] [FromBody] [Description("The stored value of the secret")]
        ApiSecretValueRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        return await DeleteSecretOfClientCoreAsync(clientId, request.ValueEncrypted);
    }

    // DELETE {tenant}/v1/apiSecrets/client/xyz/{base64(stored hash)}
    /// <summary>
    ///     Deprecated (AB#8008): the stored value travels in the URL path. Kept for one release for older octo-cli/SDK
    ///     clients; use <c>POST apiSecrets/client/{clientId}/delete</c>.
    /// </summary>
    [HttpDelete("client/{clientId}/{" + LegacySecretRouteValue + "}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Deprecated: deletes a secret of a client (stored value in the path)")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> DeleteSecretOfClient(
        [Required] [Description("ID of the client")]
        string clientId)
    {
        var value = TakeLegacySecretValue("DeleteSecretOfClient", "client", clientId);
        if (value == null)
        {
            return BadRequest();
        }

        return await DeleteSecretOfClientCoreAsync(clientId, value);
    }

    private async Task<IActionResult> DeleteSecretOfClientCoreAsync(string clientId, string storedValue)
    {
        try
        {
            // RemoveAll with a predicate (AB#7989): the list of an entity read from the database hands out new
            // wrapper instances of the stored records, so Remove(wrapper) found nothing and the secret stayed.
            // The write is version-checked, so a concurrent secret write cannot bring the removed secret back.
            var removed = 0;
            var octoClient = await _octoClientStore.MutateAsync(clientId,
                current => (removed = current.ClientSecrets.RemoveAll(x => x.Value == storedValue)) > 0);
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


    // POST {tenant}/v1/apiSecrets/apiResource/xyz/delete   body: { "valueEncrypted": "<stored hash>" }
    /// <summary>
    ///     Deletes one secret of an API resource, named by its stored value in the body (AB#8008), see
    ///     <see cref="DeleteClientSecret" />.
    /// </summary>
    [HttpPost("apiResource/{apiResourceName}/" + DeleteAction)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Deletes a secret of an API resource (stored value in the body)")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteApiResourceSecret(
        [Required] [Description("Name of the API resource")]
        string apiResourceName,
        [Required] [FromBody] [Description("The stored value of the secret")]
        ApiSecretValueRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        return await DeleteSecretOfApiResourceCoreAsync(apiResourceName, request.ValueEncrypted);
    }

    // DELETE {tenant}/v1/apiSecrets/apiResource/xyz/{base64(stored hash)}
    /// <summary>
    ///     Deprecated (AB#8008): the stored value travels in the URL path. Kept for one release for older octo-cli/SDK
    ///     clients; use <c>POST apiSecrets/apiResource/{apiResourceName}/delete</c>.
    /// </summary>
    [HttpDelete("apiResource/{apiResourceName}/{" + LegacySecretRouteValue + "}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Deprecated: deletes a secret of an API resource (stored value in the path)")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> DeleteSecretOfApiResource(
        [Required] [Description("Name of the API resource")]
        string apiResourceName)
    {
        var value = TakeLegacySecretValue("DeleteSecretOfApiResource", "apiResource", apiResourceName);
        if (value == null)
        {
            return BadRequest();
        }

        return await DeleteSecretOfApiResourceCoreAsync(apiResourceName, value);
    }

    private async Task<IActionResult> DeleteSecretOfApiResourceCoreAsync(string apiResourceName, string storedValue)
    {
        try
        {
            // RemoveAll with a predicate and a version-checked write (AB#7989), see DeleteSecretOfClientCoreAsync.
            var removed = 0;
            var apiResource = await _octoResourceStore.MutateApiResourceAsync(apiResourceName,
                current => (removed = current.ApiSecrets.RemoveAll(x => x.Value == storedValue)) > 0);
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

    // AB#8008: the action segments of the body variants, and the route value of the deprecated path variants.
    private const string DeleteAction = "delete";
    private const string LookupAction = "lookup";
    private const string LegacySecretRouteValue = "secretValue";

    /// <summary>
    ///     The single place of the deprecated path variants (AB#8008, kept for one release): reads the Base64-encoded
    ///     stored value from the route, writes one WARN without the value, and removes the value from the request trace
    ///     (<c>url.path</c>). Returns <c>null</c> when the segment is missing.
    /// </summary>
    private string? TakeLegacySecretValue(string operation, string ownerKind, string owner)
    {
        _logger.LogWarning(
            "Deprecated API secret request: {Operation} for {OwnerKind} '{Owner}' carries the secret value in the URL " +
            "path. Update octo-cli / the OctoMesh SDK; this variant is removed with the next release",
            operation, ownerKind, owner);
        Activity.Current?.SetTag("url.path", CredentialLogRedaction.Redact(Request.Path.Value ?? string.Empty));

        return RouteData.Values.TryGetValue(LegacySecretRouteValue, out var raw) && raw is string encoded &&
               !string.IsNullOrEmpty(encoded)
            ? encoded.DecodeBase64()
            : null;
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