using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using MongoDB.Bson;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Meshmakers.Octo.Services.Methods.Facades;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using System.Text.Json;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST Controller for client management
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class ClientsController : ControllerBase
{
    private const string ConcurrentChangeMessage =
        "The client was changed concurrently by other requests. Please retry.";

    private readonly IOctoClientStore _octoClientStore;
    private readonly IClientRoleStore _clientRoleStore;
    private readonly IClientImpersonationStore _clientImpersonationStore;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly IRoleChangeRefusals _roleChangeRefusals;
    private readonly IIdentityMethodFacade _methodFacade;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="octoClientStore">The storage service of clients</param>
    /// <param name="clientRoleStore">The store managing client role assignments</param>
    /// <param name="clientImpersonationStore">The store reading the MayActAs impersonation edges</param>
    /// <param name="roleManager">Resolves the role ids of a replace-all role change to names</param>
    /// <param name="roleChangeRefusals">Answers and audits a refused role change</param>
    /// <param name="methodFacade">Calls the <c>Client.*</c> methods the role and overlay endpoints are facades of</param>
    public ClientsController(IOctoClientStore octoClientStore,
        IClientRoleStore clientRoleStore,
        IClientImpersonationStore clientImpersonationStore,
        RoleManager<RtRole> roleManager,
        IRoleChangeRefusals roleChangeRefusals,
        IIdentityMethodFacade methodFacade)
    {
        _octoClientStore = octoClientStore;
        _clientRoleStore = clientRoleStore;
        _clientImpersonationStore = clientImpersonationStore;
        _roleManager = roleManager;
        _roleChangeRefusals = roleChangeRefusals;
        _methodFacade = methodFacade;
    }

    // GET: system/v1/clients
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all client definitions")]
    [ProducesResponseType(typeof(IEnumerable<ClientDto>), StatusCodes.Status200OK)]
    public async Task<IEnumerable<ClientDto>> Get()
    {
        var clients = await _octoClientStore.GetClients();
        return clients.Select(CreateClientDto);
    }

    // GET system/v1/clients/getPaged
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
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
    [Authorize(IdentityServiceConstants.IdentityDirectoryReadPolicy)]
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

    // ========================================
    // Role assignments (AssignedRole)
    // ========================================

    // GET system/v1/clients/{id}/roles
    [HttpGet("{id}/roles")]
    [Authorize(IdentityServiceConstants.IdentityDirectoryReadPolicy)]
    [EndpointSummary("Returns the role IDs directly assigned to a client.")]
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetClientRoles([Required][Description("ID of the client")] string id)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' not found."));
        }

        var roleIds = await _clientRoleStore.GetDirectRoleIdsAsync(client.RtId);
        return Ok(roleIds.ToList());
    }

    // ========================================
    // Impersonation actors (MayActAs)
    // ========================================

    /// <summary>
    ///     The <c>System.Identity/MayActAs</c> read surface (AB#5114): answers which clients hold
    ///     a MayActAs edge INTO client <paramref name="id" /> — the actors identity's token
    ///     endpoint accepts impersonation requests from. Direction-sensitive: only inbound edges
    ///     are listed, so a client that is itself an actor for other clients does not appear as
    ///     its own actor. This is the endpoint the communication controller's service-account
    ///     health aggregate verifies the impersonation edge through.
    /// </summary>
    // GET system/v1/clients/{id}/actors
    [HttpGet("{id}/actors")]
    [Authorize(IdentityServiceConstants.IdentityDirectoryReadPolicy)]
    [EndpointSummary("Returns the client IDs that may act for (impersonate) a client via MayActAs.")]
    [ProducesResponseType(typeof(List<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetClientActors([Required][Description("ID of the client")] string id)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' not found."));
        }

        var actorClientIds = await _clientImpersonationStore.GetActorClientIdsAsync(client.RtId);
        return Ok(actorClientIds.ToList());
    }

    // PUT system/v1/clients/{id}/roles
    /// <summary>
    ///     Replaces the directly assigned roles of a client. Facade of the CK method <c>Client.SetRoles-1</c>.
    /// </summary>
    /// <remarks>
    ///     The endpoint resolves the client id and the role ids (an unknown id is <c>404</c> and changes nothing) and calls
    ///     <c>Client.SetRoles</c> in-process: client grant rule of the role change guard, only the difference is
    ///     written, one <c>Identity.Method</c> audit event.
    /// </remarks>
    [HttpPut("{id}/roles")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Replaces the directly-assigned roles of a client (replace-all).")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden, "application/problem+json")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateClientRoles(
        [Required][Description("ID of the client")] string id,
        [Required][FromBody][Description("The role ids")] List<string> roleIds)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' not found."));
        }

        // REST names the roles by id, the method by name: resolve every id first, so an unknown id changes nothing.
        var roleIdsByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var roleId in roleIds)
        {
            var role = OctoObjectId.TryParse(roleId, out _) ? await _roleManager.FindByIdAsync(roleId) : null;
            if (role == null)
            {
                return NotFound(new NotFoundErrorDto($"Role with id '{roleId}' not found."));
            }

            roleIdsByName[role.Name ?? role.RtId.ToString()] = roleId;
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientSetRolesMethodId, client.RtId.ToString(),
            new ClientSetRolesParameters { RoleNames = roleIdsByName.Keys.ToList() }, User, HttpContext.RequestAborted);
        return await ToRoleFacadeResultAsync(response, client, new CkMethodFacadeOptions()
            .MapError(UserRoleMethodErrors.RoleNotFound, error => NotFound(new NotFoundErrorDto(
                $"Role with id '{RoleIdOf(error, roleIdsByName)}' not found."))));
    }

    // PUT system/v1/clients/{id}/roles/{roleName}
    /// <summary>Assigns a role to a client. Facade of the CK method <c>Client.AddRole-1</c>.</summary>
    /// <remarks>A role the client already holds directly is <c>200</c> without a write, as before.</remarks>
    [HttpPut("{id}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Assigns a single role (by name) to a client.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden, "application/problem+json")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AddClientToRole(
        [Required][Description("ID of the client")] string id,
        [Required][Description("The role name")] string roleName)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' not found."));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientAddRoleMethodId, client.RtId.ToString(),
            new ClientAddRoleParameters { RoleName = roleName }, User, HttpContext.RequestAborted);
        return await ToRoleFacadeResultAsync(response, client, new CkMethodFacadeOptions()
            .MapError(UserRoleMethodErrors.RoleNotFound,
                _ => NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found."))));
    }

    // DELETE system/v1/clients/{id}/roles/{roleName}
    /// <summary>Removes a role from a client. Facade of the CK method <c>Client.RemoveRole-1</c>.</summary>
    /// <remarks>
    ///     A role the client does not hold, and a role that does not exist, are <c>200</c> without a change, as before (the
    ///     method answers <c>ROLE_NOT_FOUND</c> for the latter).
    /// </remarks>
    [HttpDelete("{id}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Removes a single role (by name) from a client.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveClientFromRole(
        [Required][Description("ID of the client")] string id,
        [Required][Description("The role name")] string roleName)
    {
        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' not found."));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientRemoveRoleMethodId, client.RtId.ToString(),
            new ClientRemoveRoleParameters { RoleName = roleName }, User, HttpContext.RequestAborted);
        return await ToRoleFacadeResultAsync(response, client, new CkMethodFacadeOptions()
            // REST contract: an unknown role has always been 200 without a change
            .MapError(UserRoleMethodErrors.RoleNotFound, _ => Ok()));
    }

    /// <summary>
    ///     The REST answer of a client role method: <c>200</c> on success, the audited 403 problem answer of the role change
    ///     guard (WARN log and <c>Identity.RoleChangeRefused</c> record), a client that vanished as <c>404</c>, the
    ///     endpoint's own mappings, else the facade defaults.
    /// </summary>
    private async Task<IActionResult> ToRoleFacadeResultAsync(CkMethodResponse response, RtClient client,
        CkMethodFacadeOptions options)
    {
        if (RoleChangeProblems.RefusalOf(response) is { } decision)
        {
            return await _roleChangeRefusals.RefuseAsync(HttpContext, RoleChangeCaller.FromPrincipal(User), decision,
                $"client {client.ClientId}");
        }

        return response.ToActionResult(options
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound,
                _ => NotFound(new NotFoundErrorDto($"Client with id '{client.ClientId}' not found."))));
    }

    /// <summary>The role id of a <c>ROLE_NOT_FOUND</c> answer of <c>Client.SetRoles</c> (the method names the role).</summary>
    private static string RoleIdOf(CkMethodError error, IReadOnlyDictionary<string, string> roleIdsByName) =>
        error.Parameters.TryGetValue(UserRoleMethodErrors.RoleNameParameter, out var name) &&
        roleIdsByName.TryGetValue(name, out var id)
            ? id
            : name ?? string.Empty;

    // POST api/Clients
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Creates a new client")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Post(
        [Required][FromBody][Description("The client data transfer object instance")] ClientDto clientDto)
    {
        if (!ModelState.IsValid || clientDto.ClientId == null)
        {
            return BadRequest(ModelState);
        }

        if (await AuthorizeClientSecretWriteAsync(clientDto) is { } secretRefused)
        {
            return secretRefused;
        }

        // AB#9042: the facade of the static Client.CreateClient-1 (System.Identity 3.8.0). The protocol defaults of a new
        // client, the default scopes, the hash of the secret and the URI source marker are set in the method.
        var c = ChangeOf(clientDto);
        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientCreateClientMethodId, null,
            new ClientCreateClientParameters
            {
                ClientId = clientDto.ClientId, Enabled = c.Enabled, ClientName = c.ClientName, ClientUri = c.ClientUri,
                AllowedGrantTypes = c.AllowedGrantTypes, RedirectUris = c.RedirectUris,
                PostLogoutRedirectUris = c.PostLogoutRedirectUris, AllowedCorsOrigins = c.AllowedCorsOrigins,
                AllowedScopes = c.AllowedScopes, AllowOfflineAccess = c.AllowOfflineAccess,
                RequireClientSecret = c.RequireClientSecret, ClientSecret = c.ClientSecret,
                FrontChannelLogoutUri = c.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = c.FrontChannelLogoutSessionRequired,
                BackChannelLogoutUri = c.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = c.BackChannelLogoutSessionRequired,
                AutoProvisionInChildTenants = c.AutoProvisionInChildTenants
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(ClientWriteFailures("Creation of client failed.")
            .MapError(ClientCrudErrors.ClientAlreadyExists,
                _ => Conflict($"Client with id '{clientDto.ClientId}' already exists."))
            .MapSuccess(_ => new OkResult()));
    }

    // PUT api/Clients/5
    [HttpPut("{id}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
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

        if (await AuthorizeClientSecretWriteAsync(clientDto) is { } secretRefused)
        {
            return secretRefused;
        }

        // AB#9042: the facade of Client.UpdateClient-1 (System.Identity 3.8.0): one version-checked read-modify-write
        // (AB#8015) in the method; an unresolved concurrent change is 409.
        var appClient = await _octoClientStore.FindRtClientByIdAsync(id);
        if (appClient == null)
        {
            return ClientDoesNotExist(id);
        }

        var c = ChangeOf(clientDto);
        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientUpdateClientMethodId, appClient.RtId.ToString(),
            new ClientUpdateClientParameters
            {
                ClientId = c.ClientId, Enabled = c.Enabled, ClientName = c.ClientName, ClientUri = c.ClientUri,
                AllowedGrantTypes = c.AllowedGrantTypes, RedirectUris = c.RedirectUris,
                PostLogoutRedirectUris = c.PostLogoutRedirectUris, AllowedCorsOrigins = c.AllowedCorsOrigins,
                AllowedScopes = c.AllowedScopes, AllowOfflineAccess = c.AllowOfflineAccess,
                RequireClientSecret = c.RequireClientSecret, ClientSecret = c.ClientSecret,
                FrontChannelLogoutUri = c.FrontChannelLogoutUri,
                FrontChannelLogoutSessionRequired = c.FrontChannelLogoutSessionRequired,
                BackChannelLogoutUri = c.BackChannelLogoutUri,
                BackChannelLogoutSessionRequired = c.BackChannelLogoutSessionRequired,
                AutoProvisionInChildTenants = c.AutoProvisionInChildTenants
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(ClientWriteFailures("Update of client failed.")
            .MapError(IdentityCrudErrors.ConcurrentChange, _ => ConcurrentChange())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => ClientDoesNotExist(id))
            .MapSuccess(_ => new OkResult()));
    }

    // POST: system/v1/clients/{id}/overlayUris
    /// <summary>
    ///     Declarative overlay URI write (octo-tools Apply-IdentityOverlay -> octo-cli ApplyClientOverlay -> this endpoint).
    ///     Facade of the CK method <c>Client.ApplyOverlayUris-1</c>: the overlay rules (dedupe against every source, entries
    ///     written with <c>Source = "overlay:&lt;OverlayName&gt;"</c>, no write when nothing is added, CORS refresh event on
    ///     every call) live in the method.
    /// </summary>
    /// <remarks>
    ///     Status codes and the response body are unchanged, in the earlier order: <c>400</c> with the model state for an
    ///     invalid overlay name or no non-blank URI (checked before the client is looked up), <c>404</c> for an unknown client,
    ///     <c>409</c> for a concurrent change that could not be resolved.
    /// </remarks>
    [HttpPost("{id}/overlayUris")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Applies an overlay URI set to a client. Idempotent — duplicates are skipped.")]
    [ProducesResponseType(typeof(ApplyOverlayUrisResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ApplyOverlayUris(
        [Required][Description("ID of the client")] string id,
        [Required][FromBody][Description("Overlay URI declaration")] ApplyOverlayUrisDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // REST contract: a request without any non-blank URI is 400 before the client is looked up (also for an unknown
        // client). Read-only request validation; the method enforces the same rule (NO_OVERLAY_URIS, mapped below).
        if (ClientOverlayUris.CountNonWhitespace(dto.RedirectUris) +
            ClientOverlayUris.CountNonWhitespace(dto.PostLogoutRedirectUris) +
            ClientOverlayUris.CountNonWhitespace(dto.AllowedCorsOrigins) == 0)
        {
            return NoOverlayUris(nameof(dto));
        }

        var client = await _octoClientStore.FindRtClientByIdAsync(id);
        if (client == null)
        {
            return ClientDoesNotExist(id);
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientApplyOverlayUrisMethodId, client.RtId.ToString(),
            new ClientApplyOverlayUrisParameters
            {
                OverlayName = dto.OverlayName,
                RedirectUris = dto.RedirectUris,
                PostLogoutRedirectUris = dto.PostLogoutRedirectUris,
                AllowedCorsOrigins = dto.AllowedCorsOrigins
            }, User, HttpContext.RequestAborted);
        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapSuccess(result => Ok(ToApplyOverlayUrisResultDto(result.ResultJson)))
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => ClientDoesNotExist(id))
            .MapError(ClientOverlayErrors.NoOverlayUris, _ => NoOverlayUris(nameof(dto)))
            .MapError(ClientOverlayErrors.InvalidOverlayName, _ =>
            {
                ModelState.AddModelError(nameof(ApplyOverlayUrisDto.OverlayName), OverlayNameRuleMessage);
                return BadRequest(ModelState);
            })
            .MapError(ClientOverlayErrors.ConcurrentChange, _ => ConcurrentChange())
            .MapError(CkMethodErrorCodes.MethodHandlerFailed,
                _ => BadRequest(new InternalServerErrorDto("Applying the overlay URIs failed."))));
    }

    // DELETE: /{tenantId}/v1/clients/cleanOverlayEntries
    /// <summary>
    ///     Strips overlay URI entries from every client of the tenant (all <c>overlay:*</c> sources, or only
    ///     <c>overlay:&lt;overlayName&gt;</c>). Used by the DumpTenant --clean orchestration so an archive carries no overlay
    ///     entries. Facade of the static CK method <c>Client.CleanOverlayEntries-1</c>.
    /// </summary>
    /// <remarks>
    ///     Idempotent: clients without matches are never written and the cache is invalidated once, only when anything was
    ///     removed. Status codes and the response body are unchanged.
    /// </remarks>
    [HttpDelete("cleanOverlayEntries")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Strips overlay URI entries from every client in the tenant. Idempotent — clients without matches are skipped (no DB write, no cache invalidation).")]
    [ProducesResponseType(typeof(CleanOverlayEntriesResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CleanOverlayEntries(
        [FromQuery][Description("Optional overlay name. Without it, every Source matching 'overlay:*' is removed. With it, only Source == 'overlay:<overlayName>' is removed (same regex constraint as ApplyOverlayUris).")] string? overlayName = null)
    {
        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId, null,
            new ClientCleanOverlayEntriesParameters { OverlayName = overlayName }, User, HttpContext.RequestAborted);
        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapSuccess(result => Ok(ToCleanOverlayEntriesResultDto(result.ResultJson)))
            .MapError(ClientOverlayErrors.InvalidOverlayName, _ =>
            {
                ModelState.AddModelError(nameof(overlayName),
                    "overlayName may only contain letters (A-Z, a-z), digits (0-9), and the characters '.', '-', and '_'.");
                return BadRequest(ModelState);
            })
            .MapError(ClientOverlayErrors.ConcurrentChange, _ => ConcurrentChange())
            .MapError(CkMethodErrorCodes.MethodHandlerFailed,
                _ => BadRequest(new InternalServerErrorDto("Removing the overlay entries failed."))));
    }

    private const string OverlayNameRuleMessage =
        "OverlayName may only contain letters (A-Z, a-z), digits (0-9), and the characters '.', '-', and '_'.";

    private BadRequestObjectResult NoOverlayUris(string key)
    {
        ModelState.AddModelError(key,
            "At least one of RedirectUris, PostLogoutRedirectUris, or AllowedCorsOrigins must contain a non-whitespace URI.");
        return BadRequest(ModelState);
    }

    private NotFoundObjectResult ClientDoesNotExist(string id) =>
        NotFound(new NotFoundErrorDto($"Client with id '{id}' does not exist."));

    private ObjectResult ConcurrentChange() =>
        Problem(detail: ConcurrentChangeMessage, statusCode: StatusCodes.Status409Conflict);

    /// <summary>The REST body of <c>Client.ApplyOverlayUris</c>: the result record in the shape of the earlier response.</summary>
    private static ApplyOverlayUrisResultDto ToApplyOverlayUrisResultDto(string? result)
    {
        var record = Deserialize<RtClientOverlayUrisResultRecord>(result);
        return new ApplyOverlayUrisResultDto
        {
            OverlayName = record.OverlayName,
            ClientId = record.ClientId,
            RedirectUris = new ApplyOverlayUrisListCountDto
                { Added = record.RedirectUrisAdded, SkippedDuplicate = record.RedirectUrisSkipped },
            PostLogoutRedirectUris = new ApplyOverlayUrisListCountDto
                { Added = record.PostLogoutRedirectUrisAdded, SkippedDuplicate = record.PostLogoutRedirectUrisSkipped },
            AllowedCorsOrigins = new ApplyOverlayUrisListCountDto
                { Added = record.AllowedCorsOriginsAdded, SkippedDuplicate = record.AllowedCorsOriginsSkipped }
        };
    }

    /// <summary>The REST body of <c>Client.CleanOverlayEntries</c>: the result record in the shape of the earlier response.</summary>
    private static CleanOverlayEntriesResultDto ToCleanOverlayEntriesResultDto(string? result)
    {
        var record = Deserialize<RtClientOverlayCleanResultRecord>(result);
        return new CleanOverlayEntriesResultDto
        {
            OverlayName = record.OverlayName,
            ClientsAffected = record.ClientsAffected,
            TotalEntriesRemoved = record.TotalEntriesRemoved,
            ClientResults = record.ClientResults.Select(entry => new CleanOverlayEntriesClientResultDto
            {
                ClientId = entry.ClientId,
                RedirectUrisRemoved = entry.RedirectUrisRemoved,
                PostLogoutRedirectUrisRemoved = entry.PostLogoutRedirectUrisRemoved,
                AllowedCorsOriginsRemoved = entry.AllowedCorsOriginsRemoved
            }).ToList()
        };
    }

    private static T Deserialize<T>(string? resultJson) where T : class =>
        (resultJson == null ? null : JsonSerializer.Deserialize<T>(resultJson, CkMethodJson.Options))
        ?? throw new InvalidOperationException($"The method answered without a {typeof(T).Name}.");

    // DELETE api/Clients/5
    [HttpDelete("{id}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Deletes a client")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Delete([Required][Description("ID of the client")] string id)
    {
        var appClient = await _octoClientStore.FindRtClientByIdAsync(id);
        if (appClient == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' does not exist."));
        }

        // AB#9042: the facade of Client.DeleteClient-1 (System.Identity 3.8.0).
        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.ClientCkTypeId,
            SystemIdentityCkIds.ClientDeleteClientMethodId, appClient.RtId.ToString(), new ClientDeleteClientParameters(),
            User, HttpContext.RequestAborted);
        return response.ToActionResult(ClientWriteFailures("Delete of client failed.")
            .MapError(CkMethodErrorCodes.MethodTargetNotFound, _ => ClientDoesNotExist(id))
            .MapSuccess(_ => new OkResult()));
    }

    private static ClientDto CreateClientDto(RtClient applicationClient)
    {
        var clientDto = new ClientDto
        {
            RtId = applicationClient.RtId.ToString(),
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
            ProvisionedByParentTenantId = applicationClient.ProvisionedByParentTenantId,
            // Read-only DCR flags (RFC 7591, AB#4338): emitted so management surfaces can mark
            // dynamically registered clients; ApplyToClient never reads them back — they are
            // owned by DynamicClientRegistrationService and the TTL sweep exclusively.
            DynamicRegistration = applicationClient.DynamicRegistration,
            DynamicRegistrationExpiresAt = applicationClient.DynamicRegistrationExpiresAt
        };
        return clientDto;
    }

    /// <summary>
    ///     AB#5861: a <c>clientSecret</c> in the create/update body sets (replaces) the client's secret — the same power as
    ///     <c>POST apiSecrets/client/{id}</c> — so it needs <see cref="IdentityServiceConstants.IdentitySecretAdministrationPolicy" />
    ///     on top of the controller policy. Without a secret in the body nothing changes. Returns the 403 to answer
    ///     (AB#5227 shape, naming the role), or <c>null</c>.
    /// </summary>
    private async Task<IActionResult?> AuthorizeClientSecretWriteAsync(ClientDto clientDto)
    {
        if (string.IsNullOrWhiteSpace(clientDto.ClientSecret))
        {
            return null;
        }

        var result = await HttpContext.RequestServices.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(User, HttpContext, IdentityServiceConstants.IdentitySecretAdministrationPolicy);
        if (result.Succeeded)
        {
            return null;
        }

        var reason = result.Failure?.FailureReasons.FirstOrDefault()?.Message ??
                     IdentityApiAuthorizationPolicies.SecretAdministrationRequirement.DeniedMessage();
        return StatusCode(StatusCodes.Status403Forbidden, new { message = reason });
    }

    /// <summary>The change a REST body describes, as the client create and update methods take it.</summary>
    private static ClientChange ChangeOf(ClientDto dto) => new(dto.ClientId, dto.IsEnabled, dto.ClientName,
        dto.ClientUri, dto.AllowedGrantTypes?.ToList(), dto.RedirectUris?.ToList(), dto.PostLogoutRedirectUris?.ToList(),
        dto.AllowedCorsOrigins?.ToList(), dto.AllowedScopes?.ToList(), dto.IsOfflineAccessEnabled,
        dto.RequireClientSecret, dto.ClientSecret, dto.FrontChannelLogoutUri, dto.FrontChannelLogoutSessionRequired,
        dto.BackChannelLogoutUri, dto.BackChannelLogoutSessionRequired, dto.AutoProvisionInChildTenants);

    /// <summary>
    ///     The answers of a refused client write: an unexpected failure is 400 with a fixed message (the exception text is
    ///     no longer returned), a refused secret write 403 as the REST secret policy answers it.
    /// </summary>
    private CkMethodFacadeOptions ClientWriteFailures(string operation) => new CkMethodFacadeOptions()
        .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ => BadRequest(new InternalServerErrorDto(operation)))
        .MapError(CkMethodErrorCodes.MethodValidationFailed, _ => BadRequest(ModelState));
}
