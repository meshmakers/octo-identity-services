using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

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
    private readonly UserManager<RtUser> _userManager;

    public GrantsApiController(
        IIdentityServerInteractionService interaction,
        IClientStore clientStore,
        IResourceStore resourceStore,
        IEventService events,
        UserManager<RtUser> userManager)
    {
        _interaction = interaction;
        _clientStore = clientStore;
        _resourceStore = resourceStore;
        _events = events;
        _userManager = userManager;
    }

    /// <summary>
    /// Get all grants (client permissions) for the current user
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<GrantInfoDto>>> GetGrants()
    {
        var grants = await _interaction.GetAllUserGrantsAsync();
        var list = new List<GrantInfoDto>();

        foreach (var grant in grants)
        {
            var client = await _clientStore.FindClientByIdAsync(grant.ClientId);
            if (client == null) continue;

            var resources = await _resourceStore.FindResourcesByScopeAsync(grant.Scopes);

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

        await _interaction.RevokeUserConsentAsync(request.ClientId);

        await _events.RaiseAsync(new GrantsRevokedEvent(
            User.GetSubjectId(),
            request.ClientId));

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
