using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// API Controller for Angular SPA device authorization operations
/// </summary>
[ApiController]
[Route("{tenantId}/api/device")]
[Authorize]
public class DeviceApiController(
    IDeviceFlowInteractionService deviceInteraction,
    IEventService events,
    ICrossTenantAuthenticationService crossTenantAuthService,
    ICrossTenantUserProvisioningService crossTenantUserProvisioningService,
    IOctoIdentityProviderStore identityProviderStore,
    UserManager<RtUser> userManager,
    SignInManager<RtUser> signInManager,
    ILogger<DeviceApiController> logger)
    : ControllerBase
{

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

        var request = await deviceInteraction.GetAuthorizationContextAsync(userCode, HttpContext.RequestAborted);
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
        var context = await deviceInteraction.GetAuthorizationContextAsync(request.UserCode, HttpContext.RequestAborted);
        if (context == null)
        {
            return new DeviceAuthorizationResultDto
            {
                Success = false,
                ErrorMessage = "Invalid or expired device code"
            };
        }

        // Check if the authenticated user exists in the current tenant (cross-tenant scenario).
        // The user's session cookie is from a parent tenant (e.g. octosystem), authenticated
        // via the device confirmation page. The cookie subject points to a user that only exists
        // in the parent tenant's database. We need to provision a local shadow user in the child
        // tenant before approving the device code, otherwise the DeviceCodeValidator will fail
        // with invalid_grant when it can't find the user.
        var routeTenantId = RouteData.Values["tenantId"]?.ToString() ?? "System";
        var subjectId = User.GetSubjectId();
        var existingUser = await userManager.FindByIdAsync(subjectId);

        if (existingUser == null)
        {
            // User doesn't exist in the current tenant — this is a cross-tenant scenario.
            // Try to find the user's home tenant by walking up the tenant hierarchy.
            logger.LogInformation(
                "Device authorization: user '{SubjectId}' not found in tenant '{TenantId}', attempting cross-tenant provisioning",
                subjectId, routeTenantId);

            // Find which tenant the user actually belongs to by checking OctoTenantIdentityProviders
            var identityProviders = (await identityProviderStore.GetAllAsync())
                .OfType<RtOctoTenantIdentityProvider>()
                .Where(p => p.IsEnabled)
                .ToList();

            CrossTenantAuthResult? crossTenantResult = null;
            foreach (var provider in identityProviders)
            {
                crossTenantResult = await crossTenantAuthService.ValidateCrossTenantAccessAsync(
                    routeTenantId, provider.ParentTenantId!, subjectId);
                if (crossTenantResult != null)
                {
                    break;
                }
            }

            if (crossTenantResult == null)
            {
                logger.LogWarning(
                    "Cross-tenant access denied for device authorization: user '{SubjectId}' in tenant '{RouteTenant}'",
                    subjectId, routeTenantId);

                return new DeviceAuthorizationResultDto
                {
                    Success = false,
                    ErrorMessage = "Cross-tenant access denied"
                };
            }

            var localUser = await crossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync(
                crossTenantResult, routeTenantId);

            if (localUser == null)
            {
                return new DeviceAuthorizationResultDto
                {
                    Success = false,
                    ErrorMessage = "Failed to create local user in target tenant"
                };
            }

            // Re-sign-in as the local shadow user so the device code grant is associated
            // with a user that exists in the target tenant's database.
            await signInManager.SignInAsync(localUser, isPersistent: false);

            logger.LogInformation(
                "Cross-tenant device authorization: provisioned user '{UserName}' in tenant '{TenantId}'",
                localUser.UserName, routeTenantId);
        }

        var grantedConsent = new ConsentResponse
        {
            RememberConsent = request.RememberConsent,
            ScopesValuesConsented = request.ScopesConsented ?? [],
            Description = request.Description
        };

        await deviceInteraction.HandleRequestAsync(request.UserCode, grantedConsent, HttpContext.RequestAborted);

        await events.RaiseAsync(new ConsentGrantedEvent(
            User.GetSubjectId(),
            context.Client?.ClientId ?? "unknown",
            context.ValidatedResources.RawScopeValues,
            request.ScopesConsented ?? [],
            request.RememberConsent), HttpContext.RequestAborted);

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
        var context = await deviceInteraction.GetAuthorizationContextAsync(request.UserCode, HttpContext.RequestAborted);
        if (context == null)
        {
            return new DeviceAuthorizationResultDto
            {
                Success = false,
                ErrorMessage = "Invalid or expired device code"
            };
        }

        await deviceInteraction.HandleRequestAsync(
            request.UserCode,
            new ConsentResponse { Error = InteractionError.AccessDenied },
            HttpContext.RequestAborted);

        await events.RaiseAsync(new ConsentDeniedEvent(
            User.GetSubjectId(),
            context.Client?.ClientId ?? "unknown",
            context.ValidatedResources.RawScopeValues), HttpContext.RequestAborted);

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
