using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using AutoMapper;
using Duende.IdentityModel;
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

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

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
        [FromBody][Description("The configuration for the new identity provider.")] IdentityProviderDto identityProviderDto)
    {
        // ClientSecret is no longer [Required] on the DTO because PUT must accept it being omitted
        // (the existing secret is preserved). Creation still needs a secret, so enforce it here.
        if (RequiresClientSecretOnCreate(identityProviderDto, out var missingFieldName))
        {
            ModelState.AddModelError(missingFieldName, $"The {missingFieldName} field is required.");
            return ValidationProblem(ModelState);
        }

        if (!IsProviderNameValid(identityProviderDto.Name))
        {
            ModelState.AddModelError(nameof(IdentityProviderDto.Name), ProviderNameValidationMessage);
            return ValidationProblem(ModelState);
        }

        var identityProvider = _mapper.Map<RtIdentityProvider>(identityProviderDto);

        await HandleWriteExceptionAsync(async () => await _identityProviderStore.StoreAsync(identityProvider));
        await SendIdentityProviderUpdate();
        return _mapper.Map<IdentityProviderDto>(identityProvider);
    }

    // The provider Name is embedded verbatim into the just-in-time provisioned external
    // user name ("{providerName}_{email}"). ASP.NET Identity's UserValidator only accepts a
    // limited character set, so a name with spaces/parentheses/non-ASCII letters (e.g.
    // "Microsoft Entra ID") makes UserManager.CreateAsync fail with InvalidUserName, which the
    // user only sees as "Failed to create user account" AFTER a successful external login.
    // Reject such names here — the single write path shared by the Studio UI, octo-cli and the
    // MCP server — so the problem surfaces at configuration time instead of at login time.
    internal const string ProviderNameValidationMessage =
        "The Name may only contain ASCII letters, digits and the separators '.', '_' and '-' (no spaces or other special characters), because it is used to build user names for externally provisioned accounts.";

    private static readonly System.Text.RegularExpressions.Regex ProviderNameRegex =
        new("^[A-Za-z0-9._-]+$", System.Text.RegularExpressions.RegexOptions.Compiled);

    internal static bool IsProviderNameValid(string? name)
        => !string.IsNullOrWhiteSpace(name) && ProviderNameRegex.IsMatch(name);

    private static bool RequiresClientSecretOnCreate(IdentityProviderDto dto, out string missingFieldName)
    {
        missingFieldName = nameof(GoogleIdentityProviderDto.ClientSecret);
        return dto switch
        {
            GoogleIdentityProviderDto g => string.IsNullOrEmpty(g.ClientSecret),
            MicrosoftIdentityProviderDto m => string.IsNullOrEmpty(m.ClientSecret),
            FacebookIdentityProviderDto f => string.IsNullOrEmpty(f.ClientSecret),
            AzureEntraIdProviderDto a => string.IsNullOrEmpty(a.ClientSecret),
            _ => false
        };
    }

    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Delete an existing identity provider.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteIdentityProviderAsync([Required][Description("The ID of the identity provider to be deleted")] OctoObjectId rtId)
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
        [FromRoute][Required][Description("ID of an existing provider")] OctoObjectId rtId,
        [FromBody][Required][Description("The configuration for the new identity provider.")] IdentityProviderDto identityProviderDto)
    {
        if (identityProviderDto == null)
        {
            throw new ArgumentNullException(nameof(identityProviderDto));
        }

        if (!IsProviderNameValid(identityProviderDto.Name))
        {
            ModelState.AddModelError(nameof(IdentityProviderDto.Name), ProviderNameValidationMessage);
            return ValidationProblem(ModelState);
        }

        var identityProvider = _mapper.Map<RtIdentityProvider>(identityProviderDto);
        identityProvider.RtId = rtId;

        await HandleWriteExceptionAsync(async () => await _identityProviderStore.StoreAsync(identityProvider));
        await SendIdentityProviderUpdate();
        return Ok(identityProviderDto);
    }

    private static async Task HandleWriteExceptionAsync(Func<Task> action)
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