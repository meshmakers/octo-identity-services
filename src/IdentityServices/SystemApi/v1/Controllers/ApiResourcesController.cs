using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using AutoMapper;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ApiResourcesController : ControllerBase
{
    private readonly IDistributionEventHubService _distributionEventHubService;
    private readonly IMapper _mapper;
    private readonly IOctoResourceStore _octoResourceStore;

    public ApiResourcesController(IOctoResourceStore octoResourceStore, IMapper mapper,
        IDistributionEventHubService distributionEventHubService)
    {
        _octoResourceStore = octoResourceStore;
        _mapper = mapper;
        _distributionEventHubService = distributionEventHubService;
    }

    // GET: system/v1/apiResources
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all API resources definitions")]
    [ProducesResponseType(typeof(IEnumerable<ApiResourceDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get()
    {
        try
        {
            var resources = await _octoResourceStore.GetAllResourcesAsync();
            return Ok(resources.ApiResources.Select(CreateApiResourceDto));
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // GET system/v1/apiResources/getPaged
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all API resources definitions using paging")]
    [ProducesResponseType(typeof(PagedResult<ApiResourceDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Get([Required] [FromQuery] PagingParams pagingParams)
    {
        try
        {
            var list = new List<ApiResourceDto>();

            var apiResources = (await _octoResourceStore.GetAllResourcesAsync()).ApiResources;

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
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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

            var nativeApiResource = _mapper.Map<ApiResource>(apiResource);

            return Ok(CreateApiResourceDto(nativeApiResource));
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // POST api/apiResources
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Post([Required] [FromBody] ApiResourceDto apiResourceDto)
    {
        try
        {
            if (!ModelState.IsValid || apiResourceDto.Name == null)
            {
                return BadRequest(ModelState);
            }

            if ((await _octoResourceStore.FindApiResourcesByNameAsync([apiResourceDto.Name])).Any())
            {
                return Conflict($"API resource with name '{apiResourceDto.Name}' already exists.");
            }

            var apiResource = new RtApiResource();
            ApplyToRtApiResource(apiResource, apiResourceDto);

            await _octoResourceStore.CreateApiResourceAsync(apiResource);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // PUT api/apiResources/5
    [HttpPut("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates an API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Put([Required] string name, [Required] [FromBody] ApiResourceDto apiResourceDto)
    {
        try
        {
            if (!ModelState.IsValid || apiResourceDto.Name == null)
            {
                return BadRequest(ModelState);
            }

            var octoApiResource = await _octoResourceStore.GetApiResourceByNameAsync(apiResourceDto.Name);
            if (octoApiResource == null)
            {
                return NotFound(new NotFoundErrorDto($"API resource with name '{name}' does not exist."));
            }

            ApplyToRtApiResource(octoApiResource, apiResourceDto);

            await _octoResourceStore.UpdateApiResourceAsync(name, octoApiResource);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }


    // DELETE api/apiResources/5
    [HttpDelete("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes an API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(NotFoundErrorDto), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(InternalServerErrorDto), StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Delete([Required] string name)
    {
        try
        {
            var octoApiResource = await _octoResourceStore.GetApiResourceByNameAsync(name);
            if (octoApiResource == null)
            {
                return NotFound(new NotFoundErrorDto($"API resource with name '{name}' does not exist."));
            }

            await _octoResourceStore.DeleteApiResourceAsync(octoApiResource.RtId);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    private Task ClearCacheAsync()
    {
        return _distributionEventHubService.PublishAsync(new CorsClientsUpdate(_octoResourceStore.TenantId,
            Guid.NewGuid(), DateTime.Now));
    }

    private ApiResourceDto CreateApiResourceDto(ApiResource apiResource)
    {
        var apiResourceDto = new ApiResourceDto
        {
            IsEnabled = apiResource.Enabled,
            Name = apiResource.Name,
            DisplayName = apiResource.DisplayName,
            Description = apiResource.Description,
            ShowInDiscoveryDocument = apiResource.ShowInDiscoveryDocument,
            RequireResourceIndicator = apiResource.RequireResourceIndicator,
            UserClaims = apiResource.UserClaims,
            Scopes = apiResource.Scopes,
            AllowedAccessTokenSigningAlgorithms = apiResource.AllowedAccessTokenSigningAlgorithms
        };

        return apiResourceDto;
    }

    private void ApplyToRtApiResource(RtApiResource apiResource, ApiResourceDto apiResourceDto)
    {
        if (string.IsNullOrWhiteSpace(apiResourceDto.Name))
        {
            throw new InvalidOperationException("API Resource name cannot be null or empty.");
        }

        apiResource.Enabled = apiResourceDto.IsEnabled;
        apiResource.Name = apiResourceDto.Name;
        apiResource.DisplayName = apiResourceDto.DisplayName;
        apiResource.Description = apiResourceDto.Description;
        apiResource.ShowInDiscoveryDocument = apiResourceDto.ShowInDiscoveryDocument;
        apiResource.RequireResourceIndicator = apiResourceDto.RequireResourceIndicator;
        if (apiResourceDto.UserClaims != null)
        {
            apiResource.Claims = new AttributeStringValueList(apiResourceDto.UserClaims.ToList());
        }

        if (apiResourceDto.Scopes != null)
        {
            apiResource.Scopes = new AttributeStringValueList(apiResourceDto.Scopes.ToList());
        }

        apiResource.AllowedAccessTokenSigningAlgorithms = new AttributeStringValueList(
            apiResourceDto.AllowedAccessTokenSigningAlgorithms?.ToList() ?? new List<string>());
    }
}