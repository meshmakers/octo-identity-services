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
    private readonly IClientRoleStore _clientRoleStore;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="octoClientStore">The storage service of clients</param>
    /// <param name="distributionEventHubService">Distributed cache with REDIS</param>
    /// <param name="clientRoleStore">The store managing client role assignments</param>
    public ClientsController(IOctoClientStore octoClientStore,
        IDistributionEventHubService distributionEventHubService,
        IClientRoleStore clientRoleStore)
    {
        _octoClientStore = octoClientStore;
        _distributionEventHubService = distributionEventHubService;
        _clientRoleStore = clientRoleStore;
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

    // ========================================
    // Role assignments (AssignedRole)
    // ========================================

    // GET system/v1/clients/{id}/roles
    [HttpGet("{id}/roles")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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

    // PUT system/v1/clients/{id}/roles
    [HttpPut("{id}/roles")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Replaces the directly-assigned roles of a client (replace-all).")]
    [ProducesResponseType(StatusCodes.Status200OK)]
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

        await _clientRoleStore.SetRoleIdsAsync(client.RtId, roleIds);
        return Ok();
    }

    // PUT system/v1/clients/{id}/roles/{roleName}
    [HttpPut("{id}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Assigns a single role (by name) to a client.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
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

        try
        {
            await _clientRoleStore.AddRoleAsync(client.RtId, roleName);
        }
        catch (InvalidOperationException)
        {
            return NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found."));
        }

        return Ok();
    }

    // DELETE system/v1/clients/{id}/roles/{roleName}
    [HttpDelete("{id}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
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

        await _clientRoleStore.RemoveRoleAsync(client.RtId, roleName);
        return Ok();
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

    // POST: system/v1/clients/{id}/overlayUris
    // AB#4209 Step 4 — declarative overlay URI write. The cmdlet caller (octo-tools
    // Apply-IdentityOverlay → octo-cli ApplyClientOverlay → this endpoint) passes the three
    // URI lists for one client; we dedupe each against the existing list contents and append
    // new entries with Source = "overlay:<OverlayName>". The Step 2a preservation pass keeps
    // them across blueprint re-apply; the future DumpTenant --clean filter strips them from
    // sanitised exports. See concept doc §4.3 and §4.5.
    [HttpPost("{id}/overlayUris")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
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

        // Count only non-whitespace inputs so a payload like {RedirectUris: ["   ", ""]}
        // hits the same 400 as the all-null case below — both are no-op intent and the
        // endpoint should reject them up front rather than walk the dedup path for nothing.
        var meaningfulCount = CountNonWhitespace(dto.RedirectUris)
                              + CountNonWhitespace(dto.PostLogoutRedirectUris)
                              + CountNonWhitespace(dto.AllowedCorsOrigins);
        if (meaningfulCount == 0)
        {
            ModelState.AddModelError(nameof(dto),
                "At least one of RedirectUris, PostLogoutRedirectUris, or AllowedCorsOrigins must contain a non-whitespace URI.");
            return BadRequest(ModelState);
        }

        var appClient = await _octoClientStore.FindRtClientByIdAsync(id);
        if (appClient == null)
        {
            return NotFound(new NotFoundErrorDto($"Client with id '{id}' does not exist."));
        }

        var sourceTag = ClientUriSources.OverlayPrefix + dto.OverlayName;
        var redirectResult = AppendOverlayUris(appClient.RedirectUris, dto.RedirectUris, sourceTag);
        var postLogoutResult = AppendOverlayUris(appClient.PostLogoutRedirectUris, dto.PostLogoutRedirectUris, sourceTag);
        var corsResult = AppendOverlayUris(appClient.AllowedCorsOrigins, dto.AllowedCorsOrigins, sourceTag);

        // No-op short-circuit: if every incoming URI hit the dedup branch, the client entity
        // is byte-identical to what we loaded. Skipping the UpdateAsync + cache-bust holds
        // the endpoint's "re-run is no DB churn / no cache invalidation" contract — important
        // for the cmdlet caller that re-applies the overlay on every Start-Octo / CI run.
        var totalAdded = redirectResult.Added + postLogoutResult.Added + corsResult.Added;
        if (totalAdded > 0)
        {
            try
            {
                await _octoClientStore.UpdateAsync(id, appClient);
                await ClearCacheAsync();
            }
            catch (Exception e)
            {
                return BadRequest(new InternalServerErrorDto(e.Message));
            }
        }

        return Ok(new ApplyOverlayUrisResultDto
        {
            OverlayName = dto.OverlayName,
            ClientId = appClient.ClientId,
            RedirectUris = redirectResult,
            PostLogoutRedirectUris = postLogoutResult,
            AllowedCorsOrigins = corsResult
        });
    }

    // DELETE: /{tenantId}/v1/clients/cleanOverlayEntries
    // AB#4209 Step 5 PR 1 — strip overlay URI entries from every blueprint-managed
    // RtClient in the tenant. Used by the future DumpTenant --clean orchestrator
    // (bot-services clones the tenant DB to a temp DB, calls this against the temp DB,
    // mongodumps the temp DB, drops it) so the resulting archive carries no overlay:*
    // entries and is safe to re-import as Blueprint seed material.
    //
    // Without overlayName: strips every entry where Source starts with "overlay:" —
    // every overlay across every overlayName goes away.
    // With overlayName: strips only entries where Source matches "overlay:<name>"
    // exactly — useful for per-overlay clean-out (e.g. drop gerald-laptop overlays
    // but keep the shared local-dev ones).
    //
    // Idempotent — skips the UpdateAsync + cache bust for clients that had nothing to
    // remove (matches the ApplyOverlayUris no-op contract on re-runs). See concept doc
    // §4.5 (source taxonomy) and §4.7 (--clean filter rule).
    //
    // PHASE-3 MIGRATION CANDIDATE: when octo-platform-services grows to Phase 3
    // (blueprint orchestration + cross-cutting tenant operations), this endpoint and
    // the bot-services orchestration that calls it move under platform-services as the
    // central tenant-clean-export flow. The endpoint stays here because identity-services
    // is the owner of RtClient + ClientUriSources; the orchestration moves out.
    [HttpDelete("cleanOverlayEntries")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Strips overlay URI entries from every client in the tenant. Idempotent — clients without matches are skipped (no DB write, no cache invalidation).")]
    [ProducesResponseType(typeof(CleanOverlayEntriesResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CleanOverlayEntries(
        [FromQuery][Description("Optional overlay name. Without it, every Source matching 'overlay:*' is removed. With it, only Source == 'overlay:<overlayName>' is removed (same regex constraint as ApplyOverlayUris).")] string? overlayName = null)
    {
        if (overlayName != null && !System.Text.RegularExpressions.Regex.IsMatch(overlayName, "^[A-Za-z0-9._-]+$"))
        {
            ModelState.AddModelError(nameof(overlayName),
                "overlayName may only contain letters (A-Z, a-z), digits (0-9), and the characters '.', '-', and '_'.");
            return BadRequest(ModelState);
        }

        // null = "match every overlay:* prefix"; non-null = "match overlay:<name> exactly"
        var targetSource = overlayName != null
            ? ClientUriSources.OverlayPrefix + overlayName
            : null;

        var allClients = await _octoClientStore.GetClients();
        var perClientResults = new List<CleanOverlayEntriesClientResultDto>();
        var totalRemoved = 0;

        foreach (var client in allClients)
        {
            var redirectRemoved = RemoveOverlayEntries(client.RedirectUris, targetSource);
            var postLogoutRemoved = RemoveOverlayEntries(client.PostLogoutRedirectUris, targetSource);
            var corsRemoved = RemoveOverlayEntries(client.AllowedCorsOrigins, targetSource);

            var clientTotal = redirectRemoved + postLogoutRemoved + corsRemoved;
            if (clientTotal == 0)
            {
                continue;
            }

            try
            {
                await _octoClientStore.UpdateAsync(client.ClientId, client);
            }
            catch (Exception e)
            {
                return BadRequest(new InternalServerErrorDto(
                    $"Failed to update client '{client.ClientId}' after removing {clientTotal} overlay entries: {e.Message}"));
            }

            perClientResults.Add(new CleanOverlayEntriesClientResultDto
            {
                ClientId = client.ClientId,
                RedirectUrisRemoved = redirectRemoved,
                PostLogoutRedirectUrisRemoved = postLogoutRemoved,
                AllowedCorsOriginsRemoved = corsRemoved
            });
            totalRemoved += clientTotal;
        }

        // Cache invalidation is per-tenant, not per-client; bust once after the loop iff
        // anything changed, mirroring the ApplyOverlayUris contract.
        if (totalRemoved > 0)
        {
            await ClearCacheAsync();
        }

        return Ok(new CleanOverlayEntriesResultDto
        {
            OverlayName = overlayName,
            ClientsAffected = perClientResults.Count,
            TotalEntriesRemoved = totalRemoved,
            ClientResults = perClientResults
        });
    }

    /// <summary>
    ///     Removes entries from <paramref name="targetList"/> whose <c>Source</c> matches the
    ///     target. <paramref name="targetSource"/> = <c>null</c> matches every
    ///     <c>overlay:*</c> prefix; non-null matches the exact source string. Returns the
    ///     number of entries removed (0 if nothing matched).
    /// </summary>
    /// <remarks>
    ///     Walks the list in reverse so the RemoveAt indices stay valid as entries vanish.
    ///     <c>IAttributeValueList&lt;T&gt;</c> does not expose <c>RemoveAll</c>, hence the
    ///     index loop.
    /// </remarks>
    private static int RemoveOverlayEntries(
        IAttributeValueList<RtClientUriEntryRecord> targetList,
        string? targetSource)
    {
        var removed = 0;
        for (var i = targetList.Count - 1; i >= 0; i--)
        {
            var entry = targetList[i];
            var matches = targetSource != null
                ? string.Equals(entry.Source, targetSource, StringComparison.Ordinal)
                : entry.Source.StartsWith(ClientUriSources.OverlayPrefix, StringComparison.Ordinal);
            if (matches)
            {
                targetList.RemoveAt(i);
                removed++;
            }
        }
        return removed;
    }

    private static int CountNonWhitespace(List<string>? list)
    {
        if (list == null || list.Count == 0)
        {
            return 0;
        }

        var count = 0;
        foreach (var item in list)
        {
            if (!string.IsNullOrWhiteSpace(item))
            {
                count++;
            }
        }
        return count;
    }

    /// <summary>
    ///     Appends each URI from <paramref name="incoming"/> to <paramref name="targetList"/>
    ///     unless an entry with the same <c>Uri</c> already exists (regardless of source).
    ///     Returns the per-list count breakdown for the response body.
    /// </summary>
    /// <remarks>
    ///     Dedup is by URI string (Ordinal comparison) — matches the Step 2a Merge contract so
    ///     re-running the overlay apply against the same DB is a no-op. Conflict policy: any
    ///     existing source (base / api / overlay:* / family:*) wins, the overlay-incoming entry
    ///     is silently dropped. Mirrors the concept doc §4.3 "skip-duplicate" rule.
    /// </remarks>
    private static ApplyOverlayUrisListCountDto AppendOverlayUris(
        IAttributeValueList<RtClientUriEntryRecord> targetList,
        List<string>? incoming,
        string sourceTag)
    {
        if (incoming == null || incoming.Count == 0)
        {
            return new ApplyOverlayUrisListCountDto { Added = 0, SkippedDuplicate = 0 };
        }

        var existingUris = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in targetList)
        {
            existingUris.Add(entry.Uri);
        }

        var added = 0;
        var skipped = 0;
        foreach (var uri in incoming)
        {
            if (string.IsNullOrWhiteSpace(uri))
            {
                continue;
            }

            if (!existingUris.Add(uri))
            {
                skipped++;
                continue;
            }

            targetList.Add(new RtClientUriEntryRecord { Uri = uri, Source = sourceTag });
            added++;
        }

        return new ApplyOverlayUrisListCountDto { Added = added, SkippedDuplicate = skipped };
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