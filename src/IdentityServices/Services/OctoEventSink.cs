using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
/// Custom IdentityServer event sink that persists error and failure events
/// to the OctoMesh runtime event log in the affected tenant.
/// </summary>
internal class OctoEventSink(
    IEventRepository eventRepository,
    IHttpContextAccessor httpContextAccessor,
    ILogger<OctoEventSink> logger) : IEventSink
{
    public async Task PersistAsync(Event evt)
    {
        if (evt.EventType is not (EventTypes.Error or EventTypes.Failure))
        {
            return;
        }

        var message = FormatEventMessage(evt);
        var tenantId = httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;

        try
        {
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                await eventRepository.StoreErrorEvent(
                    tenantId,
                    RtEventSourcesEnum.IdentityService,
                    message);
            }
            else
            {
                await eventRepository.StoreSystemErrorEvent(
                    RtEventSourcesEnum.IdentityService,
                    message);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to persist IdentityServer event to runtime event log: {EventName}", evt.Name);
        }
    }

    private static string FormatEventMessage(Event evt)
    {
        var parts = new List<string> { $"[{evt.Name}]" };

        if (!string.IsNullOrWhiteSpace(evt.Message))
        {
            parts.Add(evt.Message);
        }

        switch (evt)
        {
            case ClientAuthenticationFailureEvent clientEvt:
                parts.Add($"ClientId: {clientEvt.ClientId}");
                break;
            case TokenIssuedFailureEvent tokenEvt:
                if (!string.IsNullOrWhiteSpace(tokenEvt.ClientId))
                    parts.Add($"ClientId: {tokenEvt.ClientId}");
                if (!string.IsNullOrWhiteSpace(tokenEvt.Error))
                    parts.Add($"Error: {tokenEvt.Error}");
                if (!string.IsNullOrWhiteSpace(tokenEvt.Scopes))
                    parts.Add($"Scopes: {tokenEvt.Scopes}");
                break;
            case UserLoginFailureEvent loginEvt:
                parts.Add($"Username: {loginEvt.Username}");
                break;
            case InvalidClientConfigurationEvent clientConfigEvt:
                parts.Add($"ClientId: {clientConfigEvt.ClientId}");
                break;
        }

        return string.Join(" - ", parts);
    }
}
