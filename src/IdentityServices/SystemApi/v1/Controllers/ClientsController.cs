using System.ComponentModel.DataAnnotations;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Common.ApiErrors;
using Meshmakers.Octo.Services.Common.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

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
    /// <summary>
    ///     Returns all client definitions
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IEnumerable<ClientDto>> Get()
    {
        var clients = await _octoClientStore.GetClients();
        return clients.Select(CreateClientDto);
    }

    // GET system/v1/clients/getPaged
    /// <summary>
    ///     Returns all clients using paging
    /// </summary>
    /// <returns></returns>
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<PagedResult<ClientDto>> Get([Required] [FromQuery] PagingParams pagingParams)
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

    // GET api/Clients/5
    /// <summary>
    ///     Returns client information based on it's client id
    /// </summary>
    /// <param name="id">Id of the client</param>
    /// <returns>An Object that describes the client.</returns>
    [HttpGet("{id}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    public async Task<IActionResult> Get([Required] string id)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return NotFound();
        }

        return Ok(CreateClientDto(client));
    }

    /// <summary>
    ///     Creates a new client
    /// </summary>
    /// <param name="clientDto">The client data transfer object instance</param>
    /// <returns></returns>
    // POST api/Clients
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Post([Required] [FromBody] ClientDto clientDto)
    {
        if (!ModelState.IsValid || clientDto.ClientId == null)
        {
            return BadRequest(ModelState);
        }

        if (await _octoClientStore.FindClientByIdAsync(clientDto.ClientId) != null)
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
            return BadRequest(new InternalServerError(e.Message));
        }
    }

    // PUT api/Clients/5
    /// <summary>
    ///     Updates a client
    /// </summary>
    /// <param name="id">Id of the client</param>
    /// <param name="clientDto">The client data transfer object instance</param>
    /// <returns></returns>
    [HttpPut("{id}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Put([Required] string id, [Required] [FromBody] ClientDto clientDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var appClient = await _octoClientStore.FindRtClientByIdAsync(id);
        if (appClient == null)
        {
            return NotFound(new NotFoundError($"Client with id '{id}' does not exist."));
        }

        ApplyToClient(appClient, clientDto);

        try
        {
            await _octoClientStore.UpdateAsync(id, appClient);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
    }

    // DELETE api/Clients/5
    /// <summary>
    ///     Deletes a client
    /// </summary>
    /// <param name="id">Id of the client</param>
    /// <returns></returns>
    [HttpDelete("{id}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    public async Task<IActionResult> Delete([Required] string id)
    {
        var appClient = await _octoClientStore.FindClientByIdAsync(id);
        if (appClient == null)
        {
            return NotFound(new NotFoundError($"Client with id '{id}' does not exist."));
        }

        try
        {
            await _octoClientStore.DeleteAsync(id);
            await ClearCacheAsync();
        }
        catch (Exception e)
        {
            return BadRequest(new InternalServerError(e.Message));
        }

        return Ok();
    }

    private Task ClearCacheAsync(string? tenantId = null)
    {
        return _distributionEventHubService.PublishAsync(new CorsClientsUpdate(tenantId));
    }

    private ClientDto CreateClientDto(RtClient applicationClient)
    {
        var clientDto = new ClientDto
        {
            IsEnabled = applicationClient.Enabled,
            ClientId = applicationClient.ClientId,
            ClientName = applicationClient.ClientName,
            ClientUri = applicationClient.ClientUri,
            AllowedGrantTypes = applicationClient.AllowedGrantTypes,
            RedirectUris = applicationClient.RedirectUris,
            PostLogoutRedirectUris = applicationClient.PostLogoutRedirectUris,
            AllowedCorsOrigins = applicationClient.AllowedCorsOrigins,
            AllowedScopes = applicationClient.AllowedScopes,
            IsOfflineAccessEnabled = applicationClient.AllowOfflineAccess
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
            applicationClient.RedirectUris = new AttributeStringValueList(
                clientDto.RedirectUris?.ToList() ?? new List<string>());
        }

        if (clientDto.PostLogoutRedirectUris != null)
        {
            applicationClient.PostLogoutRedirectUris = new AttributeStringValueList(
                clientDto.PostLogoutRedirectUris?.ToList() ??
                new List<string>());
        }

        if (clientDto.AllowedCorsOrigins != null)
        {
            applicationClient.AllowedCorsOrigins = new AttributeStringValueList(
                clientDto.AllowedCorsOrigins?.ToList() ?? new List<string>());
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

        if (!string.IsNullOrWhiteSpace(clientDto.ClientSecret))
        {
            applicationClient.ClientSecrets = new AttributeRecordValueList<RtSecretRecord>
            {
                new() { Value = clientDto.ClientSecret.Sha256() }
            };
        }
    }
}