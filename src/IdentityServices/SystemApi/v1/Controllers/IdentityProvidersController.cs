using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using AutoMapper;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

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

    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all available identity providers.")]
    [ProducesResponseType(typeof(IdentityProvidersResult), StatusCodes.Status200OK)]
    public async Task<ActionResult<IdentityProvidersResult>> GetIdentityProvidersAsync()
    {
        var identityProviders = await _identityProviderStore.GetAllAsync();
        return new IdentityProvidersResult
        {
            IdentityProviders = identityProviders.Select(_mapper.Map<IdentityProviderDto>)
        };
    }

    [HttpGet("{rtId}")]
    [ProducesResponseType(typeof(IdentityProvidersResult), StatusCodes.Status200OK)]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns an identity provider by its ID.")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IdentityProvidersResult>> Get([Required] OctoObjectId rtId)
    {
        var identityProvider = await _identityProviderStore.GetByIdAsync(rtId);
        if (identityProvider == null)
        {
            return NotFound();
        }

        return new IdentityProvidersResult
        {
            IdentityProviders = [_mapper.Map<IdentityProviderDto>(identityProvider)]
        };
    }

    [HttpPost]
    [ProducesResponseType(typeof(IdentityProviderDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Add a new identity provider.")]
    public async Task<ActionResult<IdentityProviderDto>> AddNewIdentityProviderAsync(
        [FromBody] [Description("The configuration for the new identity provider.")] IdentityProviderDto identityProviderDto)
    {
        var identityProvider = _mapper.Map<RtIdentityProvider>(identityProviderDto);

        await HandleWriteExceptionAsync(async () => await _identityProviderStore.StoreAsync(identityProvider));
        await SendIdentityProviderUpdate();
        return _mapper.Map<IdentityProviderDto>(identityProvider);
    }

    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Delete an existing identity provider.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteIdentityProviderAsync([Required] [Description("The ID of the identity provider to be deleted")] OctoObjectId rtId)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        await _identityProviderStore.RemoveAsync(rtId);
        await SendIdentityProviderUpdate();
        return Ok();
    }

    [HttpPut("{rtId}")]
    [ProducesResponseType(typeof(IdentityProviderDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Replace an existing identity provider.")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<IdentityProviderDto>> ReplaceProviderAsync(
        [FromRoute] [Required] [Description("ID of an existing provider")] OctoObjectId rtId,
        [FromBody] [Required] [Description("The configuration for the new identity provider.")] IdentityProviderDto identityProviderDto)
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
        return _distributionEventHubService.PublishAsync(new IdentityProviderUpdate(_identityProviderStore.TenantId,
            Guid.NewGuid(), DateTime.Now));
    }
}