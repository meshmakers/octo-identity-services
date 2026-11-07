using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Audit sink for the OpenIddict stack (AB#4992/AB#4995), replacing the former
///     <c>IEventService</c>/<c>OctoEventSink</c> pair with direct calls at the interaction sites.
/// </summary>
/// <remarks>
///     <para>
///         <see cref="StoreFailureAsync" /> persists error/failure events into the runtime event log of the tenant wired
///         into the request (the system tenant when there is none) — unchanged since the migration.
///     </para>
///     <para>
///         <see cref="StoreInfoAsync" /> and <see cref="StoreWarningAsync" /> (AB#8342) persist an event into an
///         <b>explicit</b> tenant, which need not be the request tenant: a cross-tenant grant is recorded in the target
///         tenant T (the request tenant) and in the source tenant S. The event name becomes the event's category, so an
///         administrator filters on it; <c>details</c> carry the structured, non-secret facts.
///     </para>
///     <para>
///         No method ever throws into the caller: a failed write is logged and the request goes on.
///     </para>
/// </remarks>
public interface IIdentityAuditService
{
    /// <summary>Persists a failure event to the runtime event log of the current tenant.</summary>
    Task StoreFailureAsync(string eventName, string message);

    /// <summary>
    ///     Persists an information (success) event into the runtime event log of <paramref name="tenantId" /> (AB#8342).
    /// </summary>
    /// <param name="tenantId">Tenant whose event log receives the event; need not be the request tenant.</param>
    /// <param name="eventName">Stable event name, stored as the event's category (for example <c>CrossTenantGrantCreated</c>).</param>
    /// <param name="message">Human-readable one-line message. Never a token, password or secret.</param>
    /// <param name="details">Structured, non-secret key/value facts, or <c>null</c>.</param>
    Task StoreInfoAsync(string tenantId, string eventName, string message,
        IReadOnlyDictionary<string, string>? details = null);

    /// <summary>
    ///     Persists a warning event (a refused, security-relevant action) into the runtime event log of
    ///     <paramref name="tenantId" /> (AB#8342). Same contract as <see cref="StoreInfoAsync" />.
    /// </summary>
    Task StoreWarningAsync(string tenantId, string eventName, string message,
        IReadOnlyDictionary<string, string>? details = null);
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

    public Task StoreInfoAsync(string tenantId, string eventName, string message,
        IReadOnlyDictionary<string, string>? details = null)
        => StoreInTenantAsync(tenantId, RtEventLevelsEnum.Information, eventName, message, details);

    public Task StoreWarningAsync(string tenantId, string eventName, string message,
        IReadOnlyDictionary<string, string>? details = null)
        => StoreInTenantAsync(tenantId, RtEventLevelsEnum.Warning, eventName, message, details);

    private async Task StoreInTenantAsync(string tenantId, RtEventLevelsEnum level, string eventName, string message,
        IReadOnlyDictionary<string, string>? details)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(tenantId))
            {
                throw new ArgumentException("An explicit tenant id is required.", nameof(tenantId));
            }

            await eventRepository.StoreEventAsync(tenantId, RtEventSourcesEnum.IdentityService, level,
                $"[{eventName}] {message}", eventName, details?.ToList());
        }
        catch (Exception ex)
        {
            // Auditing must never break the request (same rule as StoreFailureAsync).
            logger.LogWarning(ex,
                "Failed to persist identity audit event {EventName} to the runtime event log of tenant {TenantId}",
                eventName, tenantId);
        }
    }
}
