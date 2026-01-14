using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
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
public class ApiScopesController : ControllerBase
{
    private readonly IDistributionEventHubService _distributionEventHubService;
    private readonly IOctoResourceStore _octoResourceStore;

    public ApiScopesController(IOctoResourceStore octoResourceStore, IDistributionEventHubService distributionEventHubService)
    {
        _octoResourceStore = octoResourceStore;
        _distributionEventHubService = distributionEventHubService;
    }

    // GET: system/v1/apiScopes
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all API scope definitions")]
    [ProducesResponseType(typeof(IEnumerable<ApiScopeDto>), StatusCodes.Status200OK)]
    public async Task<IEnumerable<ApiScopeDto>> Get()
    {
        var resources = await _octoResourceStore.GetAllResourcesAsync();
        return resources.ApiScopes.Select(CreateApiScopeDto);
    }

    // GET system/v1/apiScopes/getPaged
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all API scope definitions using paging")]
    [ProducesResponseType(typeof(PagedResult<ApiScopeDto>), StatusCodes.Status200OK)]
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
            Response.Headers.Append("X-Pagination", header.ToJson());
        }

        return pagedResult;
    }

    // GET api/apiScopes/5
    [HttpGet("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns API scope information based on it's name")]
    [ProducesResponseType(typeof(ApiScopeDto), StatusCodes.Status200OK)]
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

    // POST api/apiScopes
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new API scope")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post([Required] [FromBody] ApiScopeDto scopeDto)
    {
        if (!ModelState.IsValid || scopeDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        if ((await _octoResourceStore.FindApiScopesByNameAsync(new[] { scopeDto.Name })).Any())
        {
            return Conflict($"Scope with name '{scopeDto.Name}' already exists.");
        }

        var apiScope = new RtApiScope();
        ApplyToApiScope(apiScope, scopeDto);

        try
        {
            await _octoResourceStore.CreateApiScopeAsync(apiScope);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }
    }

    // PUT api/apiScopes/5
    [HttpPut("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates an API scope")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Put([Required] string name, [Required] [FromBody] ApiScopeDto scopeDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var apiScope = await _octoResourceStore.GetApiScopeByNameAsync(name);
        if (apiScope == null)
        {
            return NotFound(new NotFoundErrorDto($"Scope with name '{name}' does not exist."));
        }

        ApplyToApiScope(apiScope, scopeDto);

        try
        {
            await _octoResourceStore.UpdateApiScopeAsync(name, apiScope);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }

        return Ok();
    }

    // DELETE api/apiScopes/5
    [HttpDelete("{name}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes an API scope")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Delete([Required] string name)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var octoApiScope = await _octoResourceStore.GetApiScopeByNameAsync(name);
        if (octoApiScope == null)
        {
            return NotFound(new NotFoundErrorDto($"Scope with name '{name}' does not exist."));
        }

        try
        {
            await _octoResourceStore.DeleteApiScopeAsync(octoApiScope.RtId);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }

        return Ok();
    }

    private Task ClearCacheAsync()
    {
        return _distributionEventHubService.PublishAsync(new CorsClientsUpdate(_octoResourceStore.TenantId,
            Guid.NewGuid(), DateTime.Now));
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
            IsEmphasize = apiScope.Emphasize
        };

        return apiScopeDto;
    }

    private void ApplyToApiScope(RtApiScope apiScope, ApiScopeDto apiScopeDto)
    {
        if (string.IsNullOrWhiteSpace(apiScopeDto.Name))
        {
            throw new InvalidOperationException("Scope name cannot be null or empty.");
        }

        apiScope.Enabled = apiScopeDto.IsEnabled;
        apiScope.Name = apiScopeDto.Name;
        apiScope.DisplayName = apiScopeDto.DisplayName;
        apiScope.Description = apiScopeDto.Description;
        apiScope.ShowInDiscoveryDocument = apiScopeDto.ShowInDiscoveryDocument;
        if (apiScopeDto.UserClaims != null)
        {
            apiScope.Claims = new AttributeStringValueList(apiScopeDto.UserClaims.ToList());
        }

        apiScope.IsRequired = apiScopeDto.IsRequired;
        apiScope.IsEmphasized = apiScopeDto.IsEmphasize;
    }
}