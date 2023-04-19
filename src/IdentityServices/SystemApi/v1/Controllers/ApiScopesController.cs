using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Duende.IdentityServer.Models;
using IdentityModel;
using Meshmakers.Octo.Backend.Common.ApiErrors;
using Meshmakers.Octo.Backend.DistributedCache;
using Meshmakers.Octo.Common.Shared.DataTransferObjects;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Meshmakers.Octo.SystematizedData.Persistence.SystemStores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ApiScopesController : ControllerBase
{
    private readonly IOctoResourceStore _octoResourceStore;
    private readonly IDistributedWithPubSubCache _distributedCache;

    public ApiScopesController(IOctoResourceStore octoResourceStore, IDistributedWithPubSubCache distributedCache)
    {
        _octoResourceStore = octoResourceStore;
        _distributedCache = distributedCache;
    }
    
    // GET: system/v1/apiScopes
    /// <summary>
    ///     Returns all API scope definitions
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IEnumerable<ApiScopeDto>> Get()
    {
        var resources = await _octoResourceStore.GetAllResourcesAsync();
        return resources.ApiScopes.Select(CreateApiScopeDto);
    }
    
    // GET system/v1/apiScopes/getPaged
    /// <summary>
    ///     Returns all API scope using paging
    /// </summary>
    /// <returns></returns>
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<PagedResult<ApiScopeDto>> Get([Required] [FromQuery] PagingParams pagingParams)
    {
        var list = new List<ApiScopeDto>();

        var scopes = (await _octoResourceStore.GetAllResourcesAsync()).ApiScopes;

        foreach (var apiResource in scopes.Skip(pagingParams.Skip).Take(pagingParams.Take))
        {
            var apiScopeDto = CreateApiScopeDto(apiResource);
            list.Add(apiScopeDto);
        }

        var pagedResult = new PagedResult<ApiScopeDto>(list, pagingParams.Skip, pagingParams.Take, scopes.Count);

        var header = pagedResult.GetHeader();
        if (header != null)
        {
            Response.Headers.Add("X-Pagination", header.ToJson());
        }

        return pagedResult;
    }
    
    // GET api/apiScopes/5
    /// <summary>
    ///     Returns scope information based on it's scope name
    /// </summary>
    /// <param name="name">Name of scope</param>
    /// <returns>An Object that describes the scope.</returns>
    [HttpGet("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IActionResult> Get([Required] string name)
    {
        var scopes = await _octoResourceStore.FindApiScopesByNameAsync(new[] { name });
        var scope = scopes.FirstOrDefault();
        if (scope == null)
        {
            return NotFound();
        }

        return Ok(CreateApiScopeDto(scope));
    }
    
    /// <summary>
    ///     Creates a new scope
    /// </summary>
    /// <param name="scopeDto">The scope data transfer object instance</param>
    /// <returns></returns>
    // POST api/apiScopes
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Post([Required] [FromBody] ApiScopeDto scopeDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        if ((await _octoResourceStore.FindApiScopesByNameAsync(new[]{scopeDto.Name})).Any())
        {
            return Conflict($"Scope with name '{scopeDto.Name}' already exists.");
        }

        var apiScope = new OctoApiScope();
        ApplyToApiScope(apiScope, scopeDto);

        try
        {
            await _octoResourceStore.CreateApiScopeAsync(apiScope);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }
    }
    
    // PUT api/apiScopes/5
    /// <summary>
    ///     Updates a scope
    /// </summary>
    /// <param name="name">Name of the scope</param>
    /// <param name="scopeDto">The scope data transfer object instance</param>
    /// <returns></returns>
    [HttpPut("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Put([Required] string name, [Required] [FromBody] ApiScopeDto scopeDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var apiScope = (await _octoResourceStore.FindApiScopesByNameAsync(new[] { name })).FirstOrDefault() as OctoApiScope;
        if (apiScope == null)
        {
            return NotFound(new NotFoundError($"Scope with name '{name}' does not exist."));
        }

        ApplyToApiScope(apiScope, scopeDto);

        try
        {
            await _octoResourceStore.UpdateApiScopeAsync(name, apiScope);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
    }
    
    // DELETE api/apiScopes/5
    /// <summary>
    ///     Deletes a scope
    /// </summary>
    /// <param name="name">Name of scope</param>
    /// <returns></returns>
    [HttpDelete("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Delete([Required] string name)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var octoApiScope = (await _octoResourceStore.FindApiScopesByNameAsync(new[] { name })).FirstOrDefault() as OctoApiScope;
        if (octoApiScope == null)
        {
            return NotFound(new NotFoundError($"Scope with name '{name}' does not exist."));
        }

        try
        {
            await _octoResourceStore.DeleteApiScopeAsync(octoApiScope.Id);
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
    
    private ApiScopeDto CreateApiScopeDto(ApiScope apiScope)
    {
        var apiScopeDto = new ApiScopeDto
        {
            IsEnabled = apiScope.Enabled,
            Name = apiScope.Name,
            DisplayName = apiScope.DisplayName,
            Description = apiScope.Description,
            ShowInDiscoveryDocument = apiScope.ShowInDiscoveryDocument,
            UserClaims = apiScope.UserClaims,
            IsRequired = apiScope.Required,
            IsEmphasize = apiScope.Emphasize,
        };
        
        return apiScopeDto;
    }
    
    private void ApplyToApiScope(OctoApiScope apiScope, ApiScopeDto apiScopeDto)
    {
        apiScope.Enabled = apiScopeDto.IsEnabled;
        apiScope.Name = apiScopeDto.Name;
        apiScope.DisplayName = apiScopeDto.DisplayName;
        apiScope.Description = apiScopeDto.Description;
        apiScope.ShowInDiscoveryDocument = apiScopeDto.ShowInDiscoveryDocument;
        if (apiScopeDto.UserClaims != null)
        {
            apiScope.UserClaims = apiScopeDto.UserClaims.ToList();
        }
        apiScope.Required = apiScopeDto.IsRequired;
        apiScope.Emphasize = apiScopeDto.IsEmphasize;
    }
}
