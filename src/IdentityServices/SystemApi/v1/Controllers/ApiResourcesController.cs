using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using AutoMapper;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Common.ApiErrors;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

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
    [ProducesResponseType(typeof(IEnumerable<ApiResourceDto>), 200)]
    public async Task<IEnumerable<ApiResourceDto>> Get()
    {
        var resources = await _octoResourceStore.GetAllResourcesAsync();
        return resources.ApiResources.Select(CreateApiResourceDto);
    }

    // GET system/v1/apiResources/getPaged
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all API resources definitions using paging")]
    [ProducesResponseType(typeof(PagedResult<ApiResourceDto>), 200)]
    public async Task<PagedResult<ApiResourceDto>> Get([Required] [FromQuery] PagingParams pagingParams)
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

        return pagedResult;
    }

    // GET api/apiResources/5
    [HttpGet("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns API resource information based on it's name")]
    [ProducesResponseType(typeof(ApiResourceDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> Get([Required] string name)
    {
        var apiResource = await _octoResourceStore.GetApiResourceByNameAsync(name);
        if (apiResource == null)
        {
            return NotFound();
        }

        var nativeApiResource = _mapper.Map<ApiResource>(apiResource);

        return Ok(CreateApiResourceDto(nativeApiResource));
    }

    // POST api/apiResources
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post([Required] [FromBody] ApiResourceDto apiResourceDto)
    {
        if (!ModelState.IsValid || apiResourceDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        if ((await _octoResourceStore.FindApiResourcesByNameAsync(new[] { apiResourceDto.Name })).Any())
        {
            return Conflict($"API resource with name '{apiResourceDto.Name}' already exists.");
        }

        var apiResource = new RtApiResource();
        ApplyToRtApiResource(apiResource, apiResourceDto);

        try
        {
            await _octoResourceStore.CreateApiResourceAsync(apiResource);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // PUT api/apiResources/5
    [HttpPut("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates an API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Put([Required] string name, [Required] [FromBody] ApiResourceDto apiResourceDto)
    {
        if (!ModelState.IsValid || apiResourceDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        var octoApiResource = await _octoResourceStore.GetApiResourceByNameAsync(apiResourceDto.Name);
        if (octoApiResource == null)
        {
            return NotFound(new NotFoundError($"API resource with name '{name}' does not exist."));
        }

        ApplyToRtApiResource(octoApiResource, apiResourceDto);

        try
        {
            await _octoResourceStore.UpdateApiResourceAsync(name, octoApiResource);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
    }


    // DELETE api/apiResources/5
    [HttpDelete("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes an API resource")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Delete([Required] string name)
    {
        var octoApiResource = await _octoResourceStore.GetApiResourceByNameAsync(name);
        if (octoApiResource == null)
        {
            return NotFound(new NotFoundError($"API resource with name '{name}' does not exist."));
        }

        try
        {
            await _octoResourceStore.DeleteApiResourceAsync(octoApiResource.RtId);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
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