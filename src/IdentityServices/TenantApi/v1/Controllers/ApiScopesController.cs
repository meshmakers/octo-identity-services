using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using MongoDB.Bson;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods.Facades;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ApiScopesController : ControllerBase
{
    private readonly IIdentityMethodFacade _methodFacade;
    private readonly IOctoResourceStore _octoResourceStore;

    /// <summary>
    ///     The write endpoints are facades of the <c>ApiScope.*</c> methods (in-process, one <c>Identity.Method</c> event per
    ///     call); the methods refresh the client caches after every write.
    /// </summary>
    public ApiScopesController(IOctoResourceStore octoResourceStore, IIdentityMethodFacade methodFacade)
    {
        _octoResourceStore = octoResourceStore;
        _methodFacade = methodFacade;
    }

    // GET: system/v1/apiScopes
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all API scope definitions")]
    [ProducesResponseType(typeof(IEnumerable<ApiScopeDto>), StatusCodes.Status200OK)]
    public async Task<IEnumerable<ApiScopeDto>> Get()
    {
        var resources = await _octoResourceStore.GetAllRtResourcesAsync();
        return resources.ApiScopes.Select(CreateApiScopeDto);
    }

    // GET system/v1/apiScopes/getPaged
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all API scope definitions using paging")]
    [ProducesResponseType(typeof(PagedResult<ApiScopeDto>), StatusCodes.Status200OK)]
    public async Task<PagedResult<ApiScopeDto>> Get([Required][FromQuery] PagingParams pagingParams)
    {
        var list = new List<ApiScopeDto>();

        var scopes = (await _octoResourceStore.GetAllRtResourcesAsync()).ApiScopes;

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
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns API scope information based on it's name")]
    [ProducesResponseType(typeof(ApiScopeDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> Get([Required] string name)
    {
        var scopes = await _octoResourceStore.FindRtApiScopesByNameAsync(new[] { name });
        var scope = scopes.FirstOrDefault();
        if (scope == null)
        {
            return NotFound();
        }

        return Ok(CreateApiScopeDto(scope));
    }

    // POST api/apiScopes
    /// <summary>Creates a new API scope. Facade of the static CK method <c>ApiScope.CreateApiScope-1</c>.</summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a new API scope")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post([Required][FromBody] ApiScopeDto scopeDto)
    {
        if (!ModelState.IsValid || scopeDto.Name == null)
        {
            return BadRequest(ModelState);
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiScopeCkTypeId,
            SystemIdentityCkIds.ApiScopeCreateApiScopeMethodId, null,
            new ApiScopeCreateApiScopeParameters
            {
                Name = scopeDto.Name,
                DisplayName = scopeDto.DisplayName,
                Description = scopeDto.Description,
                Enabled = scopeDto.IsEnabled,
                ShowInDiscoveryDocument = scopeDto.ShowInDiscoveryDocument,
                Required = scopeDto.IsRequired,
                Emphasized = scopeDto.IsEmphasize,
                UserClaims = scopeDto.UserClaims?.ToList()
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(ScopeFailures(scopeDto.Name, "Creation of the API scope failed."));
    }

    // PUT api/apiScopes/5
    /// <summary>Updates an API scope. Facade of the CK method <c>ApiScope.UpdateApiScope-1</c>.</summary>
    [HttpPut("{name}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Updates an API scope")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Put([Required] string name, [Required][FromBody] ApiScopeDto scopeDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var apiScope = await _octoResourceStore.GetApiScopeByNameAsync(name);
        if (apiScope == null)
        {
            return NotFound(ScopeNotFound(name));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiScopeCkTypeId,
            SystemIdentityCkIds.ApiScopeUpdateApiScopeMethodId, apiScope.RtId.ToString(),
            new ApiScopeUpdateApiScopeParameters
            {
                Name = scopeDto.Name ?? string.Empty,
                DisplayName = scopeDto.DisplayName,
                Description = scopeDto.Description,
                Enabled = scopeDto.IsEnabled,
                ShowInDiscoveryDocument = scopeDto.ShowInDiscoveryDocument,
                Required = scopeDto.IsRequired,
                Emphasized = scopeDto.IsEmphasize,
                UserClaims = scopeDto.UserClaims?.ToList()
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(ScopeFailures(scopeDto.Name, "Update of the API scope failed.")
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => NotFound(ScopeNotFound(name))));
    }

    // DELETE api/apiScopes/5
    /// <summary>Deletes an API scope. Facade of the CK method <c>ApiScope.DeleteApiScope-1</c>.</summary>
    [HttpDelete("{name}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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
            return NotFound(ScopeNotFound(name));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ApiScopeCkTypeId,
            SystemIdentityCkIds.ApiScopeDeleteApiScopeMethodId, octoApiScope.RtId.ToString(),
            new ApiScopeDeleteApiScopeParameters(), User, HttpContext.RequestAborted);
        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => NotFound(ScopeNotFound(name)))
            .MapError(CkMethodErrorCodes.MethodHandlerFailed,
                _ => BadRequest(new InternalServerErrorDto("Deletion of the API scope failed."))));
    }

    private static NotFoundErrorDto ScopeNotFound(string name) => new($"Scope with name '{name}' does not exist.");

    /// <summary>
    ///     The REST answers of a failed scope create or update: a taken name is <c>409</c> with the earlier text, a blank name
    ///     <c>400</c> with the earlier message, an unexpected failure <c>400</c> with a fixed message (no exception text).
    /// </summary>
    private CkMethodFacadeOptions ScopeFailures(string? scopeName, string failedMessage) => new CkMethodFacadeOptions()
        .MapSuccess(_ => Ok())
        .MapError(IdentityCrudErrors.ApiScopeAlreadyExists,
            _ => Conflict($"Scope with name '{scopeName}' already exists."))
        .MapError(CkMethodErrorCodes.MethodValidationFailed,
            _ => BadRequest(new InternalServerErrorDto("Scope name cannot be null or empty.")))
        .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => BadRequest(new InternalServerErrorDto(failedMessage)));

    private static ApiScopeDto CreateApiScopeDto(RtApiScope apiScope)
    {
        var apiScopeDto = new ApiScopeDto
        {
            IsEnabled = apiScope.Enabled,
            Name = apiScope.Name,
            DisplayName = apiScope.DisplayName,
            Description = apiScope.Description,
            ShowInDiscoveryDocument = apiScope.ShowInDiscoveryDocument,
            UserClaims = apiScope.Claims?.ToList() ?? [],
            IsRequired = apiScope.IsRequired,
            IsEmphasize = apiScope.IsEmphasized
        };

        return apiScopeDto;
    }
}
