using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using MongoDB.Bson;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Meshmakers.Octo.Services.RestDeprecation;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ApiResourcesController : ControllerBase
{
    private const string ConcurrentChangeMessage =
        "The API resource was changed concurrently by other requests. Please retry.";

    private readonly IIdentityMethodFacade _methodFacade;
    private readonly IOctoResourceStore _octoResourceStore;

    /// <summary>
    ///     The write endpoints are facades of the <c>ApiResource.*</c> methods (in-process, one <c>Identity.Method</c> event
    ///     per call); the methods refresh the client caches after every write.
    /// </summary>
    public ApiResourcesController(IOctoResourceStore octoResourceStore, IIdentityMethodFacade methodFacade)
    {
        _octoResourceStore = octoResourceStore;
        _methodFacade = methodFacade;
    }

    // GET: system/v1/apiResources
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all API resources definitions")]
    [ProducesResponseType(typeof(IEnumerable<ApiResourceDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get()
    {
        try
        {
            var resources = await _octoResourceStore.GetAllRtResourcesAsync();
            return Ok(resources.ApiResources.Select(CreateApiResourceDto));
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // GET system/v1/apiResources/getPaged
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all API resources definitions using paging")]
    [ProducesResponseType(typeof(PagedResult<ApiResourceDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get([Required][FromQuery] PagingParams pagingParams)
    {
        try
        {
            var list = new List<ApiResourceDto>();

            var apiResources = (await _octoResourceStore.GetAllRtResourcesAsync()).ApiResources;

            foreach (var apiResource in apiResources.Skip(pagingParams.Skip).Take(pagingParams.Take))
            {
                var apiResourceDto = CreateApiResourceDto(apiResource);
                list.Add(apiResourceDto);
            }

            var pagedResult = new PagedResult<ApiResourceDto>(list, pagingParams.Skip, pagingParams.Take, apiResources.Count);

            var header = pagedResult.GetHeader();
            if (header != null)
            {
                Response.Headers.Append("X-Pagination", header.ToJson());
            }

            return Ok(pagedResult);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // GET api/apiResources/5
    [HttpGet("{name}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns API resource information based on it's name")]
    [ProducesResponseType(typeof(ApiResourceDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get([Required] string name)
    {
        try
        {
            var apiResource = await _octoResourceStore.GetApiResourceByNameAsync(name);
            if (apiResource == null)
            {
                return NotFound();
            }

            return Ok(CreateApiResourceDto(apiResource));
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // POST api/apiResources
    /// <summary>Creates a new API resource. Facade of the static CK method <c>ApiResource.CreateApiResource-1</c>.</summary>
    [HttpPost]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.CrudMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a new API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Post([Required][FromBody] ApiResourceDto apiResourceDto)
    {
        if (!ModelState.IsValid || apiResourceDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiResourceCkTypeId,
            SystemIdentityCkIds.ApiResourceCreateApiResourceMethodId, null,
            new ApiResourceCreateApiResourceParameters
            {
                Name = apiResourceDto.Name,
                DisplayName = apiResourceDto.DisplayName,
                Description = apiResourceDto.Description,
                Enabled = apiResourceDto.IsEnabled,
                ShowInDiscoveryDocument = apiResourceDto.ShowInDiscoveryDocument,
                RequireResourceIndicator = apiResourceDto.RequireResourceIndicator,
                UserClaims = apiResourceDto.UserClaims?.ToList(),
                Scopes = apiResourceDto.Scopes?.ToList(),
                AllowedAccessTokenSigningAlgorithms = apiResourceDto.AllowedAccessTokenSigningAlgorithms?.ToList()
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(ResourceFailures(apiResourceDto.Name, "Creation of the API resource failed."));
    }

    // PUT api/apiResources/5
    /// <summary>
    ///     Updates an API resource. Facade of the CK method <c>ApiResource.UpdateApiResource-1</c>: one version-checked
    ///     read-modify-write that keeps the stored secrets (the DTO carries none).
    /// </summary>
    [HttpPut("{name}")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.CrudMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Updates an API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Put([Required] string name, [Required][FromBody] ApiResourceDto apiResourceDto)
    {
        if (!ModelState.IsValid || apiResourceDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        var apiResource = await _octoResourceStore.GetApiResourceByNameAsync(name);
        if (apiResource == null)
        {
            return NotFound(ResourceNotFound(name));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiResourceCkTypeId,
            SystemIdentityCkIds.ApiResourceUpdateApiResourceMethodId, apiResource.RtId.ToString(),
            new ApiResourceUpdateApiResourceParameters
            {
                Name = apiResourceDto.Name,
                DisplayName = apiResourceDto.DisplayName,
                Description = apiResourceDto.Description,
                Enabled = apiResourceDto.IsEnabled,
                ShowInDiscoveryDocument = apiResourceDto.ShowInDiscoveryDocument,
                RequireResourceIndicator = apiResourceDto.RequireResourceIndicator,
                UserClaims = apiResourceDto.UserClaims?.ToList(),
                Scopes = apiResourceDto.Scopes?.ToList(),
                AllowedAccessTokenSigningAlgorithms = apiResourceDto.AllowedAccessTokenSigningAlgorithms?.ToList()
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(ResourceFailures(apiResourceDto.Name, "Update of the API resource failed.")
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => NotFound(ResourceNotFound(name)))
            .MapError(IdentityCrudErrors.ConcurrentChange,
                _ => Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict)));
    }


    // DELETE api/apiResources/5
    /// <summary>Deletes an API resource with its secrets. Facade of the CK method <c>ApiResource.DeleteApiResource-1</c>.</summary>
    [HttpDelete("{name}")]
    [OctoRestDeprecated(Wave = IdentityRestDeprecation.Wave2, Link = IdentityRestDeprecation.CrudMethodsLink)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Deletes an API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Delete([Required] string name)
    {
        var apiResource = await _octoResourceStore.GetApiResourceByNameAsync(name);
        if (apiResource == null)
        {
            return NotFound(ResourceNotFound(name));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiResourceCkTypeId,
            SystemIdentityCkIds.ApiResourceDeleteApiResourceMethodId, apiResource.RtId.ToString(),
            new ApiResourceDeleteApiResourceParameters(), User, HttpContext.RequestAborted);
        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => NotFound(ResourceNotFound(name)))
            .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => StatusCode(StatusCodes.Status500InternalServerError,
                new InternalServerErrorDto("Deletion of the API resource failed."))));
    }

    private static NotFoundErrorDto ResourceNotFound(string name) =>
        new($"API resource with name '{name}' does not exist.");

    /// <summary>
    ///     The REST answers of a failed resource create or update: a taken name is <c>409</c> with the earlier text, a blank
    ///     name the earlier <c>500</c> message, an unexpected failure <c>500</c> with a fixed message (no exception text).
    /// </summary>
    private CkMethodFacadeOptions ResourceFailures(string resourceName, string failedMessage) =>
        new CkMethodFacadeOptions()
            .MapSuccess(_ => Ok())
            .MapError(IdentityCrudErrors.ApiResourceAlreadyExists,
                _ => Conflict($"API resource with name '{resourceName}' already exists."))
            .MapError(CkMethodErrorCodes.MethodValidationFailed, _ => StatusCode(
                StatusCodes.Status500InternalServerError,
                new InternalServerErrorDto("API Resource name cannot be null or empty.")))
            .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => StatusCode(StatusCodes.Status500InternalServerError,
                new InternalServerErrorDto(failedMessage)));

    private static ApiResourceDto CreateApiResourceDto(RtApiResource apiResource)
    {
        var apiResourceDto = new ApiResourceDto
        {
            IsEnabled = apiResource.Enabled,
            Name = apiResource.Name,
            DisplayName = apiResource.DisplayName,
            Description = apiResource.Description,
            ShowInDiscoveryDocument = apiResource.ShowInDiscoveryDocument,
            RequireResourceIndicator = apiResource.RequireResourceIndicator,
            UserClaims = apiResource.Claims?.ToList() ?? [],
            Scopes = apiResource.Scopes?.ToList() ?? [],
            AllowedAccessTokenSigningAlgorithms = apiResource.AllowedAccessTokenSigningAlgorithms?.ToList() ?? []
        };

        return apiResourceDto;
    }
}
