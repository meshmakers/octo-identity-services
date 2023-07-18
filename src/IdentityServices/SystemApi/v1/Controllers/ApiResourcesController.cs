using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel;
using Meshmakers.Octo.Backend.Common.ApiErrors;
using Meshmakers.Octo.Common.Shared;
using Meshmakers.Octo.Common.Shared.DataTransferObjects;
using Meshmakers.Octo.Common.Shared.DistributedCache;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Meshmakers.Octo.SystematizedData.Persistence.SystemStores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ApiResourcesController : ControllerBase
{
    private readonly IOctoResourceStore _octoResourceStore;
    private readonly IDistributedWithPubSubCache _distributedCache;

    public ApiResourcesController(IOctoResourceStore octoResourceStore, IDistributedWithPubSubCache distributedCache)
    {
        _octoResourceStore = octoResourceStore;
        _distributedCache = distributedCache;
    }
    
    // GET: system/v1/apiResources
    /// <summary>
    ///     Returns all API resources definitions
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IEnumerable<ApiResourceDto>> Get()
    {
        var resources = await _octoResourceStore.GetAllResourcesAsync();
        return resources.ApiResources.Cast<OctoApiResource>().Select(CreateApiResourceDto);
    }
    
    // GET system/v1/apiResources/getPaged
    /// <summary>
    ///     Returns all API resources using paging
    /// </summary>
    /// <returns></returns>
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<PagedResult<ApiResourceDto>> Get([Required] [FromQuery] PagingParams pagingParams)
    {
        var list = new List<ApiResourceDto>();

        var apiResources = (await _octoResourceStore.GetAllResourcesAsync()).ApiResources;

        foreach (var apiResource in apiResources.Cast<OctoApiResource>().Skip(pagingParams.Skip).Take(pagingParams.Take))
        {
            var apiResourceDto = CreateApiResourceDto(apiResource);
            list.Add(apiResourceDto);
        }

        var pagedResult = new PagedResult<ApiResourceDto>(list, pagingParams.Skip, pagingParams.Take, apiResources.Count);

        var header = pagedResult.GetHeader();
        if (header != null)
        {
            Response.Headers.Add("X-Pagination", header.ToJson());
        }

        return pagedResult;
    }
    
    // GET api/apiResources/5
    /// <summary>
    ///     Returns API resource information based on it's name
    /// </summary>
    /// <param name="name">Name of API resource</param>
    /// <returns>An Object that describes the API resource.</returns>
    [HttpGet("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IActionResult> Get([Required] string name)
    {
        var apiResources = await _octoResourceStore.FindApiResourcesByNameAsync(new[] { name });
        var apiResource = apiResources.FirstOrDefault() as OctoApiResource;
        if (apiResource == null)
        {
            return NotFound();
        }

        return Ok(CreateApiResourceDto(apiResource));
    }
    
    /// <summary>
    ///     Creates a new API resource
    /// </summary>
    /// <param name="apiResourceDto">The API resource data transfer object instance</param>
    /// <returns></returns>
    // POST api/apiResources
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Post([Required] [FromBody] ApiResourceDto apiResourceDto)
    {
        if (!ModelState.IsValid || apiResourceDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        if ((await _octoResourceStore.FindApiResourcesByNameAsync(new[]{apiResourceDto.Name})).Any())
        {
            return Conflict($"API resource with name '{apiResourceDto.Name}' already exists.");
        }

        var apiResource = new OctoApiResource();
        ApplyToApiResource(apiResource, apiResourceDto);

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
    /// <summary>
    ///     Updates an API resource
    /// </summary>
    /// <param name="name">Name of the API resource</param>
    /// <param name="apiResourceDto">The API resource data transfer object instance</param>
    /// <returns></returns>
    [HttpPut("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Put([Required] string name, [Required] [FromBody] ApiResourceDto apiResourceDto)
    {
        if (!ModelState.IsValid || apiResourceDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        var octoApiResource = (await _octoResourceStore.FindApiResourcesByNameAsync(new[] { apiResourceDto.Name })).FirstOrDefault() as OctoApiResource;
        if (octoApiResource == null)
        {
            return NotFound(new NotFoundError($"API resource with name '{name}' does not exist."));
        }

        ApplyToApiResource(octoApiResource, apiResourceDto);

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
    /// <summary>
    ///     Deletes an API resource
    /// </summary>
    /// <param name="name">Name of API resource</param>
    /// <returns></returns>
    [HttpDelete("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Delete([Required] string name)
    {
        var octoApiResource = (await _octoResourceStore.FindApiResourcesByNameAsync(new[] { name })).FirstOrDefault() as OctoApiResource;
        if (octoApiResource == null)
        {
            return NotFound(new NotFoundError($"API resource with name '{name}' does not exist."));
        }

        try
        {
            await _octoResourceStore.DeleteApiResourceAsync(octoApiResource.Id);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
    }
    
    private async Task ClearCacheAsync()
    {
        await _distributedCache.PublishAsync(CacheCommon.KeyCorsClients, Guid.NewGuid().ToString());
    }
    
    private ApiResourceDto CreateApiResourceDto(OctoApiResource apiResource)
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
            AllowedAccessTokenSigningAlgorithms = apiResource.AllowedAccessTokenSigningAlgorithms,
        };

        return apiResourceDto;
    }
    
    private void ApplyToApiResource(OctoApiResource apiResource, ApiResourceDto apiResourceDto)
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
            apiResource.UserClaims = apiResourceDto.UserClaims;
        }
        if (apiResourceDto.Scopes != null)
        {
            apiResource.Scopes = apiResourceDto.Scopes;
        }
        apiResource.AllowedAccessTokenSigningAlgorithms = apiResourceDto.AllowedAccessTokenSigningAlgorithms?.ToList() ?? new List<string>();

    }
}
