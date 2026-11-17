using System.Diagnostics;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Logging;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
// AB#5861: reads (list, lookup) keep IdentityTenantAdministrationReadPolicy — they return metadata and the stored
// one-way hash, never a clear text. Every write (create, rotate, delete) needs IdentitySecretAdministrationPolicy
// (role SecretManagement, staged by IdentityApiAuthorization:SecretManagementRoleEnforcement).
// AB#9037: every write is a facade of a Client.* / ApiResource.* secret method (docs/identity-rest-facades.md); the reads
// stay REST reads (secrets are not exposed through GraphQL).
public class ApiSecretsController : ControllerBase
{
    private readonly IOctoClientStore _octoClientStore;
    private readonly IOctoResourceStore _octoResourceStore;
    private readonly IIdentityMethodFacade _methodFacade;
    private readonly ILogger<ApiSecretsController> _logger;

    /// <param name="octoClientStore">Resolves the OAuth client id of the route to the method target</param>
    /// <param name="octoResourceStore">Resolves the API resource name of the route to the method target</param>
    /// <param name="methodFacade">
    ///     Calls the secret methods the write endpoints are facades of (AB#9037): <c>Client.AddSecret/UpdateSecret/RemoveSecret</c>
    ///     and <c>ApiResource.AddSecret/UpdateSecret/RemoveSecret</c>, in-process, outside any request transaction
    /// </param>
    /// <param name="logger">Logger</param>
    public ApiSecretsController(IOctoClientStore octoClientStore, IOctoResourceStore octoResourceStore,
        IIdentityMethodFacade methodFacade, ILogger<ApiSecretsController> logger)
    {
        _octoClientStore = octoClientStore;
        _octoResourceStore = octoResourceStore;
        _methodFacade = methodFacade;
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
    /// <summary>Creates a new secret for a client. Facade of the CK method <c>Client.AddSecret-1</c> (AB#9037).</summary>
    [HttpPost("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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

        var client = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound();
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientAddSecretMethodId, client.RtId.ToString(),
            new ClientAddSecretParameters { Description = request.Description, ExpirationDate = request.ExpirationDate },
            User, HttpContext.RequestAborted);
        return response.ToActionResult(AddSecretOptions(request)
            .MapError(ClientSecretMethodErrors.ClientSecretNotRequired, _ =>
            {
                ModelState.AddModelError(nameof(clientId), ClientSecretNotRequiredMessage);
                return BadRequest(ModelState);
            }));
    }

    // POST system/v1/apiSecrets/apiResource/xyz
    /// <summary>Creates a new secret for an API resource. Facade of the CK method <c>ApiResource.AddSecret-1</c> (AB#9037).</summary>
    [HttpPost("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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

        var apiResource = await FindApiResourceAsync(apiResourceName);
        if (apiResource == null)
        {
            return NotFound();
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiResourceCkTypeId,
            SystemIdentityCkIds.ApiResourceAddSecretMethodId, apiResource.RtId.ToString(),
            new ApiResourceAddSecretParameters
            {
                Description = request.Description, ExpirationDate = request.ExpirationDate
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(AddSecretOptions(request));
    }

    // PUT system/v1/apiSecrets/client/xyz
    /// <summary>Updates a secret of a client. Facade of the CK method <c>Client.UpdateSecret-1</c> (AB#9037).</summary>
    [HttpPut("client/{clientId}")]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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

        var client = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return NotFound();
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientUpdateSecretMethodId, client.RtId.ToString(),
            new ClientUpdateSecretParameters
            {
                SecretValue = apiSecretDto.ValueEncrypted,
                Description = apiSecretDto.Description,
                ExpirationDate = apiSecretDto.ExpirationDate
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(WriteSecretOptions(NotFound(), "Updating the secret failed."));
    }

    // PUT system/v1/apiSecrets/apiResource/xyz
    /// <summary>Updates a secret of an API resource. Facade of the CK method <c>ApiResource.UpdateSecret-1</c> (AB#9037).</summary>
    [HttpPut("apiResource/{apiResourceName}")]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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

        var apiResource = await FindApiResourceAsync(apiResourceName);
        if (apiResource == null)
        {
            return NotFound();
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiResourceCkTypeId,
            SystemIdentityCkIds.ApiResourceUpdateSecretMethodId, apiResource.RtId.ToString(),
            new ApiResourceUpdateSecretParameters
            {
                SecretValue = apiSecretDto.ValueEncrypted,
                Description = apiSecretDto.Description,
                ExpirationDate = apiSecretDto.ExpirationDate
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(WriteSecretOptions(NotFound(), "Updating the secret failed."));
    }


    // POST {tenant}/v1/apiSecrets/client/xyz/delete   body: { "valueEncrypted": "<stored hash>" }
    /// <summary>
    ///     Deletes one secret of a client, named by its stored value in the body (AB#8008). A POST sub-resource, not a
    ///     DELETE with a body: a DELETE body has no defined semantics (RFC 9110) and proxies and client libraries may drop
    ///     it; the API already uses POST sub-resources for actions (<c>users/{userName}/revokeSessions</c>). Facade of the CK
    ///     method <c>Client.RemoveSecret-1</c> (AB#9037).
    /// </summary>
    [HttpPost("client/{clientId}/" + DeleteAction)]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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
    ///     clients; use <c>POST apiSecrets/client/{clientId}/delete</c>. Facade of <c>Client.RemoveSecret-1</c> (AB#9037).
    /// </summary>
    [HttpDelete("client/{clientId}/{" + LegacySecretRouteValue + "}")]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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
        var clientMissing = NotFound(new NotFoundErrorDto($"Client with id '{clientId}' does not exist."));
        var client = await _octoClientStore.FindRtClientByIdAsync(clientId);
        if (client == null)
        {
            return clientMissing;
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientRemoveSecretMethodId, client.RtId.ToString(),
            new ClientRemoveSecretParameters { SecretValue = storedValue }, User, HttpContext.RequestAborted);
        return response.ToActionResult(WriteSecretOptions(clientMissing, "Deleting the secret failed."));
    }


    // POST {tenant}/v1/apiSecrets/apiResource/xyz/delete   body: { "valueEncrypted": "<stored hash>" }
    /// <summary>
    ///     Deletes one secret of an API resource, named by its stored value in the body (AB#8008), see
    ///     <see cref="DeleteClientSecret" />. Facade of the CK method <c>ApiResource.RemoveSecret-1</c> (AB#9037).
    /// </summary>
    [HttpPost("apiResource/{apiResourceName}/" + DeleteAction)]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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
    ///     clients; use <c>POST apiSecrets/apiResource/{apiResourceName}/delete</c>. Facade of
    ///     <c>ApiResource.RemoveSecret-1</c> (AB#9037).
    /// </summary>
    [HttpDelete("apiResource/{apiResourceName}/{" + LegacySecretRouteValue + "}")]
    [Authorize(IdentityServiceConstants.IdentitySecretAdministrationPolicy)]
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
        var apiResource = await FindApiResourceAsync(apiResourceName);
        if (apiResource == null)
        {
            return NotFound();
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiResourceCkTypeId,
            SystemIdentityCkIds.ApiResourceRemoveSecretMethodId, apiResource.RtId.ToString(),
            new ApiResourceRemoveSecretParameters { SecretValue = storedValue }, User, HttpContext.RequestAborted);
        return response.ToActionResult(WriteSecretOptions(NotFound(), "Deleting the secret failed."));
    }

    private async Task<RtApiResource?> FindApiResourceAsync(string apiResourceName) =>
        (await _octoResourceStore.FindRtApiResourcesByNameAsync(new[] { apiResourceName })).FirstOrDefault();

    /// <summary>
    ///     The REST answer of an add: the earlier body (clear text shown once, the stored hash, the request's expiration date and
    ///     description), else the shared write mappings. The clear text is only read from the in-process envelope here; it is
    ///     never logged.
    /// </summary>
    private CkMethodFacadeOptions AddSecretOptions(CreateApiSecretRequestDto request) =>
        WriteSecretOptions(NotFound(), "Creating the secret failed.")
            .MapSuccess(response =>
            {
                var clearText = response.ResultJson == null
                    ? null
                    : JsonSerializer.Deserialize<string>(response.ResultJson);
                if (string.IsNullOrEmpty(clearText))
                {
                    return BadRequest(new InternalServerErrorDto("Creating the secret failed."));
                }

                return Ok(new ApiSecretDto
                {
                    ValueClearText = clearText,
                    ValueEncrypted = OctoSecretHasher.HashSecret(clearText),
                    ExpirationDate = request.ExpirationDate,
                    Description = request.Description
                });
            });

    /// <summary>
    ///     The mappings every secret write shares: success <c>200</c> empty, the owner gone <paramref name="ownerMissing" />,
    ///     no secret with the value <c>404</c> (never echoing the value), a lost concurrent write <c>409</c>, a validation
    ///     failure <c>400</c> with the field, any other failure <c>400</c> with a fixed message (no exception text leaves the
    ///     service). Refusals (<c>METHOD_FORBIDDEN</c>) keep the default <c>403</c> problem.
    /// </summary>
    private CkMethodFacadeOptions WriteSecretOptions(IActionResult ownerMissing, string failedMessage) =>
        new CkMethodFacadeOptions()
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => ownerMissing)
            .MapError(ClientSecretMethodErrors.SecretNotFound, _ => NotFound(new NotFoundErrorDto(SecretNotFoundMessage)))
            .MapError(ClientSecretMethodErrors.ConcurrentChange,
                _ => Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict))
            .MapError(CkMethodErrorCodes.MethodValidationFailed, error =>
            {
                ModelState.AddModelError(error.Parameters.GetValueOrDefault("field") ?? "request",
                    ValidationMessage(error.Parameters.GetValueOrDefault("field")));
                return BadRequest(ModelState);
            })
            .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => BadRequest(new InternalServerErrorDto(failedMessage)));

    private static string ValidationMessage(string? field) => field switch
    {
        "expirationDate" => "The expiration date must lie in the future.",
        "description" => "This description is reserved.",
        _ => "The request is invalid."
    };

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

    private const string ClientSecretNotRequiredMessage =
        "The client does not use a secret (RequireClientSecret is false).";

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
}