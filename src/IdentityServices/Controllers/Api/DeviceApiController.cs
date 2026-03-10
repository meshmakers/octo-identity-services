using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for Angular SPA device authorization operations
/// </summary>
[ApiController]
[Route("{tenantId}/api/device")]
[Authorize]
public class DeviceApiController : ControllerBase
{
    private readonly IDeviceFlowInteractionService _deviceInteraction;
    private readonly IEventService _events;

    public DeviceApiController(
        IDeviceFlowInteractionService deviceInteraction,
        IEventService events)
    {
        _deviceInteraction = deviceInteraction;
        _events = events;
    }

    /// <summary>
    /// Get device authorization context
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<DeviceAuthorizationContextDto>> GetContext([FromQuery] string? userCode)
    {
        if (string.IsNullOrEmpty(userCode))
        {
            return BadRequest("User code is required");
        }

        var request = await _deviceInteraction.GetAuthorizationContextAsync(userCode);
        if (request == null)
        {
            return NotFound("Invalid or expired device code");
        }

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

        return new DeviceAuthorizationContextDto
        {
            UserCode = userCode,
            ClientName = request.Client?.ClientName ?? request.Client?.ClientId,
            ClientUrl = request.Client?.ClientUri,
            ClientLogoUrl = request.Client?.LogoUri,
            IdentityScopes = identityScopes,
            ApiScopes = apiScopes,
            ConfirmUserCode = true
        };
    }

    /// <summary>
    /// Authorize the device
    /// </summary>
    [HttpPost("authorize")]
    public async Task<ActionResult<DeviceAuthorizationResultDto>> Authorize([FromBody] DeviceAuthorizationRequestDto request)
    {
        var context = await _deviceInteraction.GetAuthorizationContextAsync(request.UserCode);
        if (context == null)
        {
            return new DeviceAuthorizationResultDto
            {
                Success = false,
                ErrorMessage = "Invalid or expired device code"
            };
        }

        var grantedConsent = new ConsentResponse
        {
            RememberConsent = request.RememberConsent,
            ScopesValuesConsented = request.ScopesConsented ?? [],
            Description = request.Description
        };

        await _deviceInteraction.HandleRequestAsync(request.UserCode, grantedConsent);

        await _events.RaiseAsync(new ConsentGrantedEvent(
            User.GetSubjectId(),
            context.Client?.ClientId ?? "unknown",
            context.ValidatedResources.RawScopeValues,
            request.ScopesConsented ?? [],
            request.RememberConsent));

        return new DeviceAuthorizationResultDto
        {
            Success = true
        };
    }

    /// <summary>
    /// Deny device authorization
    /// </summary>
    [HttpPost("deny")]
    public async Task<ActionResult<DeviceAuthorizationResultDto>> Deny([FromBody] DeviceDenyRequestDto request)
    {
        var context = await _deviceInteraction.GetAuthorizationContextAsync(request.UserCode);
        if (context == null)
        {
            return new DeviceAuthorizationResultDto
            {
                Success = false,
                ErrorMessage = "Invalid or expired device code"
            };
        }

        await _deviceInteraction.HandleRequestAsync(
            request.UserCode,
            new ConsentResponse { Error = AuthorizationError.AccessDenied });

        await _events.RaiseAsync(new ConsentDeniedEvent(
            User.GetSubjectId(),
            context.Client?.ClientId ?? "unknown",
            context.ValidatedResources.RawScopeValues));

        return new DeviceAuthorizationResultDto
        {
            Success = true
        };
    }
}

#region DTOs

public record DeviceAuthorizationContextDto
{
    public string UserCode { get; init; } = string.Empty;
    public string? ClientName { get; init; }
    public string? ClientUrl { get; init; }
    public string? ClientLogoUrl { get; init; }
    public IEnumerable<ScopeItemDto> IdentityScopes { get; init; } = [];
    public IEnumerable<ScopeItemDto> ApiScopes { get; init; } = [];
    public bool ConfirmUserCode { get; init; }
    public string? Description { get; init; }
}

public record DeviceAuthorizationRequestDto
{
    public string UserCode { get; init; } = string.Empty;
    public IEnumerable<string>? ScopesConsented { get; init; }
    public bool RememberConsent { get; init; }
    public string? Description { get; init; }
}

public record DeviceDenyRequestDto
{
    public string UserCode { get; init; } = string.Empty;
}

public record DeviceAuthorizationResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

#endregion
