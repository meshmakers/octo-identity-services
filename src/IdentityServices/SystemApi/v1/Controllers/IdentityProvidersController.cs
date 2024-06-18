using System.ComponentModel.DataAnnotations;
using AutoMapper;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

/// <summary>
///     REST Controller for identity provider management
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class IdentityProvidersController : ControllerBase
{
    private readonly IDistributionEventHubService _distributionEventHubService;
    private readonly IOctoIdentityProviderStore _identityProviderStore;
    private readonly IMapper _mapper;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="identityProviderStore"></param>
    /// <param name="mapper"></param>
    /// <param name="distributionEventHubService"></param>
    public IdentityProvidersController(IOctoIdentityProviderStore identityProviderStore, IMapper mapper,
        IDistributionEventHubService distributionEventHubService)
    {
        _identityProviderStore = identityProviderStore;
        _mapper = mapper;
        _distributionEventHubService = distributionEventHubService;
    }

    /// <summary>
    ///     Returns all identity providers.
    /// </summary>
    /// <response code="200">Returns all available identity providers.</response>
    /// <response code="401">Unauthorized. You need to authenticate in order to use the API.</response>
    [HttpGet]
    [ProducesResponseType(typeof(IdentityProvidersResult), StatusCodes.Status200OK)]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<ActionResult<IdentityProvidersResult>> GetIdentityProvidersAsync()
    {
        var identityProviders = await _identityProviderStore.GetAllAsync();
        return new IdentityProvidersResult
        {
            IdentityProviders = identityProviders.Select(_mapper.Map<IdentityProviderDto>)
        };
    }

    /// <summary>
    ///     Returns identity provider information based on it's name
    /// </summary>
    /// <param name="rtId">ID of the identity provider</param>
    /// <returns>An Object that describes the identity provider.</returns>
    [HttpGet("{rtId}")]
    [ProducesResponseType(typeof(IdentityProvidersResult), StatusCodes.Status200OK)]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<ActionResult<IdentityProvidersResult>> Get([Required] OctoObjectId rtId)
    {
        var identityProvider = await _identityProviderStore.GetByIdAsync(rtId);
        if (identityProvider == null)
        {
            return NotFound();
        }

        return new IdentityProvidersResult
        {
            IdentityProviders = new[] { _mapper.Map<IdentityProviderDto>(identityProvider) }
        };
    }

    /// <summary>
    ///     Add a new identity provider.
    /// </summary>
    /// <param name="identityProviderDto">The configuration for the new identity provider.</param>
    /// <response code="200">The new identity provider has been added successfully. </response>
    /// <response code="400">The new identity provider could not be created because one or multiple fields were invalid. </response>
    /// <response code="401">Unauthorized. You need to authenticate in order to use the API.</response>
    /// <returns>Returns the configuration for the new identity provider.</returns>
    [HttpPost]
    [ProducesResponseType(typeof(IdentityProviderDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<ActionResult<IdentityProviderDto>> AddNewIdentityProviderAsync(
        [FromBody] IdentityProviderDto identityProviderDto)
    {
        var identityProvider = _mapper.Map<RtIdentityProvider>(identityProviderDto);
        
        await HandleWriteExceptionAsync(async () => await _identityProviderStore.StoreAsync(identityProvider));
        await SendIdentityProviderUpdate();
        return _mapper.Map<IdentityProviderDto>(identityProvider);
    }

    /// <summary>
    ///     Delete an existing identity provider.
    /// </summary>
    /// <param name="rtId">The ID of the identity provider to be deleted</param>
    /// <response code="200">The identity provider was deleted.</response>
    /// <response code="401">Unauthorized. You need to authenticate in order to use the API.</response>
    /// <response code="404">The identity provider to be deleted does not exist.</response>
    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> DeleteIdentityProviderAsync([Required] OctoObjectId rtId)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        await _identityProviderStore.RemoveAsync(rtId);
        await SendIdentityProviderUpdate();
        return Ok();
    }

    /// <summary>
    ///     Replace the data of an existing provider.
    /// </summary>
    /// <remarks>Updates an existing provider with the specified ID with the provided data.</remarks>
    /// <param name="rtId">ID of an existing provider</param>
    /// <param name="identityProviderDto">The configuration for the new identity provider.</param>
    /// <response code="200">Returns the provider.</response>
    /// <response code="400">
    ///     The provider could not be replaced/updated either due to invalid input or failure replace
    ///     the provider when another provider with the same clientId already exists.
    /// </response>
    /// <response code="401">Unauthorized. You need to authenticate in order to use the API.</response>
    /// <response code="404">Provider with this ID not found.</response>
    [HttpPut("{rtId}")]
    [ProducesResponseType(typeof(IdentityProviderDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<ActionResult<IdentityProviderDto>> ReplaceProviderAsync([FromRoute] [Required] OctoObjectId rtId,
        [FromBody] [Required] IdentityProviderDto identityProviderDto)
    {
        if (identityProviderDto == null)
        {
            throw new ArgumentNullException(nameof(identityProviderDto));
        }

        var identityProvider = _mapper.Map<RtIdentityProvider>(identityProviderDto);
        identityProvider.RtId = rtId;

        await HandleWriteExceptionAsync(async () => await _identityProviderStore.StoreAsync(identityProvider));
        await SendIdentityProviderUpdate();
        return Ok(identityProviderDto);
    }

    private async Task HandleWriteExceptionAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (DuplicateKeyException ex)
        {
            // Currently, only the alias must be unique. Mongodb does not provide an easy way of finding out which unique property was violated.
            throw new DuplicateKeyException("Name must be unique", typeof(IdentityProviderDto),
                new[] { nameof(IdentityProviderDto.Name) }, ex);
        }
    }

    private Task SendIdentityProviderUpdate()
    {
        return _distributionEventHubService.PublishAsync(new IdentityProviderUpdate(_identityProviderStore.TenantId));
    }
}