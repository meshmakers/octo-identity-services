using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for Angular SPA grants management (viewing and revoking client permissions)
/// </summary>
[ApiController]
[Route("{tenantId}/api/grants")]
[Authorize]
public class GrantsApiController : ControllerBase
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IClientStore _clientStore;
    private readonly IResourceStore _resourceStore;
    private readonly IEventService _events;

    public GrantsApiController(
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IResourceStore resourceStore,
        IEventService events)
    {
        _interaction = interaction;
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _events = events;
    }

    /// <summary>
    /// Get all grants (client permissions) for the current user
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<GrantInfoDto>>> GetGrants()
    {
        var grants = await _interaction.GetAllUserGrantsAsync(HttpContext.RequestAborted);
        var list = new List<GrantInfoDto>();

        foreach (var grant in grants)
        {
            var client = await _clientStore.FindClientByIdAsync(grant.ClientId, HttpContext.RequestAborted);
            if (client == null) continue;

            var resources = await _resourceStore.FindResourcesByScopeAsync(grant.Scopes, HttpContext.RequestAborted);

            var identityScopes = resources.IdentityResources
                .Select(r => r.DisplayName ?? r.Name)
                .ToList();

            var apiScopes = resources.ApiScopes
                .Select(s => s.DisplayName ?? s.Name)
                .ToList();

            list.Add(new GrantInfoDto
            {
                ClientId = grant.ClientId,
                ClientName = client.ClientName ?? client.ClientId,
                ClientUrl = client.ClientUri,
                ClientLogoUrl = client.LogoUri,
                Description = client.Description,
                Created = grant.CreationTime,
                Expires = grant.Expiration,
                IdentityGrantNames = identityScopes,
                ApiGrantNames = apiScopes
            });
        }

        return list;
    }

    /// <summary>
    /// Revoke a specific client's grant (remove their access)
    /// </summary>
    [HttpPost("revoke")]
    public async Task<ActionResult<RevokeGrantResultDto>> RevokeGrant([FromBody] RevokeGrantRequestDto request)
    {
        if (string.IsNullOrEmpty(request.ClientId))
        {
            return new RevokeGrantResultDto
            {
                Success = false,
                ErrorMessage = "Client ID is required"
            };
        }

        await _interaction.RevokeUserConsentAsync(request.ClientId, HttpContext.RequestAborted);

        await _events.RaiseAsync(new GrantsRevokedEvent(
            User.GetSubjectId(),
            request.ClientId), HttpContext.RequestAborted);

        return new RevokeGrantResultDto { Success = true };
    }
}

#region DTOs

public record GrantInfoDto
{
    public string ClientId { get; init; } = string.Empty;
    public string? ClientName { get; init; }
    public string? ClientUrl { get; init; }
    public string? ClientLogoUrl { get; init; }
    public string? Description { get; init; }
    public DateTime Created { get; init; }
    public DateTime? Expires { get; init; }
    public IEnumerable<string> IdentityGrantNames { get; init; } = [];
    public IEnumerable<string> ApiGrantNames { get; init; } = [];
}

public record RevokeGrantRequestDto
{
    public string ClientId { get; init; } = string.Empty;
}

public record RevokeGrantResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

#endregion
