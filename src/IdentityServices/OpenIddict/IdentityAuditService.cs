using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Audit sink for the OpenIddict stack (AB#4992/AB#4995), replacing the former
///     <c>IEventService</c>/<c>OctoEventSink</c> pair with direct calls at the interaction sites.
///     Matching the previous behavior, only error/failure events are persisted to the OctoMesh
///     runtime event log (tenant-scoped when a tenant is wired into the request); success events
///     are log-only in the callers.
/// </summary>
public interface IIdentityAuditService
{
    /// <summary>Persists a failure event to the runtime event log of the current tenant.</summary>
    Task StoreFailureAsync(string eventName, string message);
}

internal class IdentityAuditService(
    IEventRepository eventRepository,
    IHttpContextAccessor httpContextAccessor,
    ILogger<IdentityAuditService> logger) : IIdentityAuditService
{
    public async Task StoreFailureAsync(string eventName, string message)
    {
        var tenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        var formatted = $"[{eventName}] {message}";

        try
        {
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                await eventRepository.StoreErrorEvent(tenantId, RtEventSourcesEnum.IdentityService, formatted);
            }
            else
            {
                await eventRepository.StoreSystemErrorEvent(RtEventSourcesEnum.IdentityService, formatted);
            }
        }
        catch (Exception ex)
        {
            // Auditing must never break the auth flow itself (OctoEventSink parity).
            logger.LogWarning(ex, "Failed to persist identity audit event to runtime event log: {EventName}",
                eventName);
        }
    }
}
