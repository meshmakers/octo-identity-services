using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Duende.IdentityServer.Models;
using MongoDB.Bson;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST Controller for client management
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ClientsController : ControllerBase
{
    private readonly IDistributionEventHubService _distributionEventHubService;
    private readonly IOctoClientStore _octoClientStore;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="octoClientStore">The storage service of clients</param>
    /// <param name="distributionEventHubService">Distributed cache with REDIS</param>
    public ClientsController(IOctoClientStore octoClientStore, IDistributionEventHubService distributionEventHubService)
    {
        _octoClientStore = octoClientStore;
        _distributionEventHubService = distributionEventHubService;
    }

    // GET: system/v1/clients
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all client definitions")]
    [ProducesResponseType(typeof(IEnumerable<ClientDto>), StatusCodes.Status200OK)]
    public async Task<IEnumerable<ClientDto>> Get()
    {
        var clients = await _octoClientStore.GetClients();
        return clients.Select(CreateClientDto);
    }

    // GET system/v1/clients/getPaged
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all client definitions using paging")]
    [ProducesResponseType(typeof(PagedResult<ClientDto>), StatusCodes.Status200OK)]
    public async Task<PagedResult<ClientDto>> Get([Required][FromQuery] PagingParams pagingParams)
    {
        var list = new List<ClientDto>();

        var clients = (await _octoClientStore.GetClients()).ToArray();

        foreach (var applicationUser in clients.Skip(pagingParams.Skip).Take(pagingParams.Take))
        {
            var clientDto = CreateClientDto(applicationUser);
            list.Add(clientDto);
        }

        var pagedResult = new PagedResult<ClientDto>(list, pagingParams.Skip, pagingParams.Take, clients.Count());

        var header = pagedResult.GetHeader();
        if (header != null)
        {
            Response.Headers.Append("X-Pagination", header.ToJson());
        }

        return pagedResult;
    }

    [HttpGet("{id}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns client information based on it's client id")]
    [ProducesResponseType(typeof(ClientDto), StatusCodes.Status200OK)]
    public async Task<IActionResult> Get([Required][Description("ID of the client")] string id)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return NotFound();
        }

        return Ok(CreateClientDto(client));
    }

    // POST api/Clients
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Creates a new client")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post(
        [Required][FromBody][Description("The client data transfer object instance")] ClientDto clientDto)
    {
        if (!ModelState.IsValid || clientDto.ClientId == null)
        {
            return BadRequest(ModelState);
        }

        if (await _octoClientStore.FindClientByIdAsync(clientDto.ClientId, HttpContext.RequestAborted) != null)
        {
            return Conflict($"Client with id '{clientDto.ClientId}' already exists.");
        }

        var appClient = new RtClient
        {
            RequirePkce = true,
            RequireClientSecret = false,

            AccessTokenType = RtTokenTypeEnum.Jwt,
            AllowAccessTokensViaBrowser = true,
            AlwaysIncludeUserClaimsInIdToken = true,
            RequireConsent = false
        };
        ApplyToClient(appClient, clientDto);

        try
        {
            await _octoClientStore.CreateAsync(appClient);
            await ClearCacheAsync();
            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }
    }

    // PUT api/Clients/5
    [HttpPut("{id}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Updates a client")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Put(
        [Required][Description("ID of the client")] string id,
        [Required][FromBody][Description("The client data transfer object instance")] ClientDto clientDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var appClient = await _octoClientStore.FindRtClientByIdAsync(id);
        if (appClient == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' does not exist."));
        }

        ApplyToClient(appClient, clientDto);

        try
        {
            await _octoClientStore.UpdateAsync(id, appClient);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerErrorDto(e.Message));
        }

        return Ok();
    }

    // DELETE api/Clients/5
    [HttpDelete("{id}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Deletes a client")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Delete([Required][Description("ID of the client")] string id)
    {
        var appClient = await _octoClientStore.FindClientByIdAsync(id, HttpContext.RequestAborted);
        if (appClient == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' does not exist."));
        }

        try
        {
            await _octoClientStore.DeleteAsync(id);
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
        return _distributionEventHubService.PublishAsync(new CorsClientsUpdate(_octoClientStore.TenantId,
            Guid.NewGuid(), DateTime.Now));
    }

    private static ClientDto CreateClientDto(RtClient applicationClient)
    {
        var clientDto = new ClientDto
        {
            IsEnabled = applicationClient.Enabled,
            ClientId = applicationClient.ClientId,
            ClientName = applicationClient.ClientName,
            ClientUri = applicationClient.ClientUri,
            AllowedGrantTypes = applicationClient.AllowedGrantTypes,
            RedirectUris = applicationClient.RedirectUris.Select(e => e.Uri).ToList(),
            PostLogoutRedirectUris = applicationClient.PostLogoutRedirectUris.Select(e => e.Uri).ToList(),
            AllowedCorsOrigins = applicationClient.AllowedCorsOrigins.Select(e => e.Uri).ToList(),
            AllowedScopes = applicationClient.AllowedScopes,
            IsOfflineAccessEnabled = applicationClient.AllowOfflineAccess,
            // Single Logout (SLO) fields
            FrontChannelLogoutUri = applicationClient.FrontChannelLogoutUri,
            FrontChannelLogoutSessionRequired = applicationClient.FrontChannelLogoutSessionRequired,
            BackChannelLogoutUri = applicationClient.BackChannelLogoutUri,
            BackChannelLogoutSessionRequired = applicationClient.BackChannelLogoutSessionRequired,
            RequireClientSecret = applicationClient.RequireClientSecret,
            AutoProvisionInChildTenants = applicationClient.AutoProvisionInChildTenants,
            ProvisionedByParentTenantId = applicationClient.ProvisionedByParentTenantId
        };
        return clientDto;
    }

    private void ApplyToClient(RtClient applicationClient, ClientDto clientDto)
    {
        if (clientDto.IsEnabled.HasValue)
        {
            applicationClient.Enabled = clientDto.IsEnabled.Value;
        }

        if (!string.IsNullOrEmpty(clientDto.ClientId))
        {
            applicationClient.ClientId = clientDto.ClientId;
        }

        if (!string.IsNullOrEmpty(clientDto.ClientName))
        {
            applicationClient.ClientName = clientDto.ClientName;
        }

        if (!string.IsNullOrEmpty(clientDto.ClientUri))
        {
            applicationClient.ClientUri = clientDto.ClientUri;
        }

        if (clientDto.AllowedGrantTypes != null)
        {
            applicationClient.AllowedGrantTypes = new AttributeStringValueList(
                clientDto.AllowedGrantTypes?.ToList() ?? new List<string>());
        }

        if (clientDto.RedirectUris != null)
        {
            applicationClient.RedirectUris = WrapAsApiSourcedUris(clientDto.RedirectUris);
        }

        if (clientDto.PostLogoutRedirectUris != null)
        {
            applicationClient.PostLogoutRedirectUris = WrapAsApiSourcedUris(clientDto.PostLogoutRedirectUris);
        }

        if (clientDto.AllowedCorsOrigins != null)
        {
            applicationClient.AllowedCorsOrigins = WrapAsApiSourcedUris(clientDto.AllowedCorsOrigins);
        }

        if (clientDto.AllowedScopes != null)
        {
            applicationClient.AllowedScopes = new AttributeStringValueList(
                CommonConstants.OctoDefaultScopes.Concat(clientDto.AllowedScopes).Distinct().ToList());
        }
        else
        {
            applicationClient.AllowedScopes = new AttributeStringValueList(CommonConstants.OctoDefaultScopes.ToList());
        }

        if (clientDto.IsOfflineAccessEnabled.HasValue)
        {
            applicationClient.AllowOfflineAccess = clientDto.IsOfflineAccessEnabled.Value;
        }

        if (clientDto.RequireClientSecret.HasValue)
        {
            applicationClient.RequireClientSecret = clientDto.RequireClientSecret.Value;
        }

        if (!string.IsNullOrWhiteSpace(clientDto.ClientSecret))
        {
            applicationClient.ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
            {
                new() { Value = clientDto.ClientSecret.Sha256() }
            };
        }

        // Single Logout (SLO) fields
        if (!string.IsNullOrEmpty(clientDto.FrontChannelLogoutUri))
        {
            applicationClient.FrontChannelLogoutUri = clientDto.FrontChannelLogoutUri;
        }

        if (clientDto.FrontChannelLogoutSessionRequired.HasValue)
        {
            applicationClient.FrontChannelLogoutSessionRequired = clientDto.FrontChannelLogoutSessionRequired.Value;
        }

        if (!string.IsNullOrEmpty(clientDto.BackChannelLogoutUri))
        {
            applicationClient.BackChannelLogoutUri = clientDto.BackChannelLogoutUri;
        }

        if (clientDto.BackChannelLogoutSessionRequired.HasValue)
        {
            applicationClient.BackChannelLogoutSessionRequired = clientDto.BackChannelLogoutSessionRequired.Value;
        }

        // Phase 1 multi-tenant client credentials (#4042–#4047). When the caller sets
        // AutoProvisionInChildTenants on POST or PUT, it lands on the RtClient.
        // ClientStore.UpdateAsync's post-commit hook (#4044) then fans out to mirrors.
        // For initial CREATE the flag is recorded but no backfill happens until the
        // operator triggers provisionInExistingTenants or a new tenant is created —
        // matches the PATCH behaviour for symmetry.
        if (clientDto.AutoProvisionInChildTenants.HasValue)
        {
            applicationClient.AutoProvisionInChildTenants = clientDto.AutoProvisionInChildTenants.Value;
        }
    }

    /// <summary>
    ///     Wraps a caller-supplied list of URI strings as <see cref="ClientUriEntry"/> records with
    ///     <c>Source = <see cref="ClientUriSources.Api"/></c> — the cleanup gate then preserves
    ///     these entries across blueprint re-applies (an operator who added a URI through the API
    ///     meant it to be persistent; see concept §4.5).
    /// </summary>
    private static AttributeRecordValueList<RtClientUriEntryRecord> WrapAsApiSourcedUris(IEnumerable<string>? uris)
    {
        var list = new AttributeRecordValueList<RtClientUriEntryRecord>();
        if (uris == null)
        {
            return list;
        }

        foreach (var uri in uris)
        {
            list.Add(new RtClientUriEntryRecord { Uri = uri, Source = ClientUriSources.Api });
        }

        return list;
    }
}