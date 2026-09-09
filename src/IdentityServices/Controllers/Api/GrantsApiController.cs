using System.Security.Claims;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
///     API Controller for Angular SPA grants management (viewing and revoking client permissions).
///     Backed by <see cref="IOctoInteractionService" /> over the OpenIddict authorization/token
///     stores (AB#4995): a grant is a remembered consent (permanent authorization) or a client
///     holding a live refresh token. Routes and DTOs are unchanged.
/// </summary>
[ApiController]
[Route("{tenantId}/api/grants")]
[Authorize]
public class GrantsApiController(
    IOctoInteractionService interactionService,
    IOctoClientStore clientStore,
    ILogger<GrantsApiController> logger) : ControllerBase
{
    /// <summary>
    /// Get all grants (client permissions) for the current user
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<GrantInfoDto>>> GetGrants()
    {
        var grants = await interactionService.GetAllUserGrantsAsync(GetSubjectId());
        var list = new List<GrantInfoDto>();

        foreach (var grant in grants)
        {
            var client = await clientStore.FindRtClientByIdAsync(grant.ClientId);
            if (client == null)
            {
                continue;
            }

            var (identityScopes, apiScopes) = await interactionService.ResolveScopeItemsAsync(grant.Scopes);

            list.Add(new GrantInfoDto
            {
                ClientId = grant.ClientId,
                ClientName = client.ClientName ?? client.ClientId,
                ClientUrl = client.ClientUri,
                ClientLogoUrl = client.LogoUri,
                Description = client.Description,
                Created = grant.Created,
                Expires = grant.Expires,
                IdentityGrantNames = identityScopes.Select(s => s.DisplayName).ToList(),
                ApiGrantNames = apiScopes.Select(s => s.DisplayName).ToList()
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

        await interactionService.RevokeUserConsentAsync(GetSubjectId(), request.ClientId);

        logger.LogInformation("Grants revoked by '{Subject}' for client '{ClientId}'",
            GetSubjectId(), request.ClientId);

        return new RevokeGrantResultDto { Success = true };
    }

    private string GetSubjectId() =>
        User.FindFirstValue(Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier) ??
        throw new InvalidOperationException("The authenticated user has no subject claim.");
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
