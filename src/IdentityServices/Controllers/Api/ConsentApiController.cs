using System.Security.Claims;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
///     API Controller for Angular SPA consent operations. Backed by
///     <see cref="IOctoInteractionService" /> (AB#4995): the consent decision is round-tripped to
///     the authorize endpoint via the data-protected <c>octo_consent</c> parameter on the
///     returned redirect URL; remembered consent is persisted as a permanent OAuth authorization.
///     Routes and DTOs are unchanged from the pre-migration implementation — the Angular SPA
///     needs no changes.
/// </summary>
[ApiController]
[Route("{tenantId}/api/consent")]
[Authorize]
public class ConsentApiController(
    IOctoInteractionService interactionService,
    ILogger<ConsentApiController> logger) : ControllerBase
{
    /// <summary>
    /// Get the consent context
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<ConsentContextDto>> GetConsentContext([FromQuery] string? returnUrl)
    {
        var context = await interactionService.GetAuthorizationContextAsync(returnUrl);
        if (context == null)
        {
            return NotFound("Invalid consent request");
        }

        var client = context.Client;
        var (identityScopes, apiScopes) = await interactionService.ResolveScopeItemsAsync(context.Scopes);
        var offlineAccess = context.Scopes.Contains(Scopes.OfflineAccess);

        return new ConsentContextDto
        {
            ReturnUrl = returnUrl ?? string.Empty,
            ClientName = client.ClientName ?? client.ClientId,
            ClientUrl = client.ClientUri,
            ClientLogoUrl = client.LogoUri,
            IdentityScopes = identityScopes,
            ApiScopes = apiScopes,
            AllowRememberConsent = client.AllowRememberConsent,
            Description = offlineAccess ? "This application requests offline access" : null
        };
    }

    /// <summary>
    /// Grant consent
    /// </summary>
    [HttpPost("grant")]
    public async Task<ActionResult<ConsentResultDto>> GrantConsent([FromBody] ConsentRequestDto request)
    {
        var context = await interactionService.GetAuthorizationContextAsync(request.ReturnUrl);
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

        var redirectUrl = await interactionService.GrantConsentAsync(
            context, GetSubjectId(), request.ScopesConsented.ToList(), request.RememberConsent,
            request.Description);

        logger.LogInformation("Consent granted by '{Subject}' for client '{ClientId}' (remember: {Remember})",
            GetSubjectId(), context.Client.ClientId, request.RememberConsent);

        return new ConsentResultDto
        {
            Success = true,
            RedirectUrl = redirectUrl
        };
    }

    /// <summary>
    /// Deny consent
    /// </summary>
    [HttpPost("deny")]
    public async Task<ActionResult<ConsentResultDto>> DenyConsent([FromBody] ConsentDenyRequestDto request)
    {
        var context = await interactionService.GetAuthorizationContextAsync(request.ReturnUrl);
        if (context == null)
        {
            return new ConsentResultDto
            {
                Success = false,
                ErrorMessage = "Invalid consent request"
            };
        }

        var redirectUrl = interactionService.DenyConsent(context, GetSubjectId());

        logger.LogInformation("Consent denied by '{Subject}' for client '{ClientId}'",
            GetSubjectId(), context.Client.ClientId);

        return new ConsentResultDto
        {
            Success = true,
            RedirectUrl = redirectUrl
        };
    }

    private string GetSubjectId() =>
        User.FindFirstValue(Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier) ??
        throw new InvalidOperationException("The authenticated user has no subject claim.");
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
