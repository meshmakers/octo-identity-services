using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for Angular SPA consent operations
/// </summary>
[ApiController]
[Route("{tenantId}/api/consent")]
[Authorize]
public class ConsentApiController : ControllerBase
{
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;

    public ConsentApiController(
        IIdentityServerInteractionService interaction,
        IEventService events)
    {
        _interaction = interaction;
        _events = events;
    }

    /// <summary>
    /// Get the consent context
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<ConsentContextDto>> GetConsentContext([FromQuery] string? returnUrl)
    {
        var request = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (request == null)
        {
            return NotFound("Invalid consent request");
        }

        var client = request.Client;

        var identityScopes = request.ValidatedResources.Resources.IdentityResources
            .Select(r => new ScopeItemDto
            {
                Name = r.Name,
                DisplayName = r.DisplayName ?? r.Name,
                Description = r.Description,
                Emphasize = r.Emphasize,
                Required = r.Required,
                Checked = true
            })
            .ToList();

        if (request.ValidatedResources.Resources.OfflineAccess)
        {
            identityScopes.Add(new ScopeItemDto
            {
                Name = Duende.IdentityServer.IdentityServerConstants.StandardScopes.OfflineAccess,
                DisplayName = "Offline Access",
                Description = "Access to your applications when you are offline",
                Emphasize = true,
                Required = false,
                Checked = true
            });
        }

        var apiScopes = request.ValidatedResources.Resources.ApiScopes
            .Select(s => new ScopeItemDto
            {
                Name = s.Name,
                DisplayName = s.DisplayName ?? s.Name,
                Description = s.Description,
                Emphasize = s.Emphasize,
                Required = s.Required,
                Checked = true
            })
            .ToList();

        return new ConsentContextDto
        {
            ReturnUrl = returnUrl ?? string.Empty,
            ClientName = client.ClientName ?? client.ClientId,
            ClientUrl = client.ClientUri,
            ClientLogoUrl = client.LogoUri,
            IdentityScopes = identityScopes,
            ApiScopes = apiScopes,
            AllowRememberConsent = client.AllowRememberConsent,
            Description = request.ValidatedResources.Resources.OfflineAccess ? "This application requests offline access" : null
        };
    }

    /// <summary>
    /// Grant consent
    /// </summary>
    [HttpPost("grant")]
    public async Task<ActionResult<ConsentResultDto>> GrantConsent([FromBody] ConsentRequestDto request)
    {
        var context = await _interaction.GetAuthorizationContextAsync(request.ReturnUrl);
        if (context == null)
        {
            return new ConsentResultDto
            {
                Success = false,
                ErrorMessage = "Invalid consent request"
            };
        }

        if (request.ScopesConsented == null || !request.ScopesConsented.Any())
        {
            return new ConsentResultDto
            {
                Success = false,
                ValidationError = "You must select at least one permission"
            };
        }

        var grantedConsent = new ConsentResponse
        {
            RememberConsent = request.RememberConsent,
            ScopesValuesConsented = request.ScopesConsented,
            Description = request.Description
        };

        await _interaction.GrantConsentAsync(context, grantedConsent);

        await _events.RaiseAsync(new ConsentGrantedEvent(
            User.GetSubjectId(),
            context.Client.ClientId,
            context.ValidatedResources.RawScopeValues,
            request.ScopesConsented,
            request.RememberConsent));

        return new ConsentResultDto
        {
            Success = true,
            RedirectUrl = request.ReturnUrl
        };
    }

    /// <summary>
    /// Deny consent
    /// </summary>
    [HttpPost("deny")]
    public async Task<ActionResult<ConsentResultDto>> DenyConsent([FromBody] ConsentDenyRequestDto request)
    {
        var context = await _interaction.GetAuthorizationContextAsync(request.ReturnUrl);
        if (context == null)
        {
            return new ConsentResultDto
            {
                Success = false,
                ErrorMessage = "Invalid consent request"
            };
        }

        await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

        await _events.RaiseAsync(new ConsentDeniedEvent(
            User.GetSubjectId(),
            context.Client.ClientId,
            context.ValidatedResources.RawScopeValues));

        return new ConsentResultDto
        {
            Success = true,
            RedirectUrl = request.ReturnUrl
        };
    }
}

#region DTOs

public record ConsentContextDto
{
    public string ReturnUrl { get; init; } = string.Empty;
    public string ClientName { get; init; } = string.Empty;
    public string? ClientUrl { get; init; }
    public string? ClientLogoUrl { get; init; }
    public IEnumerable<ScopeItemDto> IdentityScopes { get; init; } = [];
    public IEnumerable<ScopeItemDto> ApiScopes { get; init; } = [];
    public bool AllowRememberConsent { get; init; }
    public string? Description { get; init; }
}

public record ScopeItemDto
{
    public string Name { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string? Description { get; init; }
    public bool Emphasize { get; init; }
    public bool Required { get; init; }
    public bool Checked { get; init; }
}

public record ConsentRequestDto
{
    public string? ReturnUrl { get; init; }
    public IEnumerable<string>? ScopesConsented { get; init; }
    public bool RememberConsent { get; init; }
    public string? Description { get; init; }
}

public record ConsentDenyRequestDto
{
    public string? ReturnUrl { get; init; }
}

public record ConsentResultDto
{
    public bool Success { get; init; }
    public string? RedirectUrl { get; init; }
    public string? ErrorMessage { get; init; }
    public string? ValidationError { get; init; }
}

#endregion
