using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands.Payloads;
using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     E-mail OTP delivery for the AB#5123 self-service e-mail modality (AB#5135), the
///     <see cref="OtpDeliveryChannelKind.Email" /> counterpart of the phone
///     <see cref="SignalRestOtpDeliveryChannel" />. It REUSES identity's existing e-mail transport —
///     the distribution-event-hub seam the <c>INotificationService</c> / <c>UserEmailInteractionService</c>
///     e-mail-confirmation &amp; password-reset paths publish onto — by emitting a
///     <see cref="SendNotificationsRequest" /> with a single <see cref="DistNotificationDto" /> whose
///     recipient is the enrolling user's own address. No new SMTP client is introduced: the tenant's
///     mail pipeline (the mesh-adapter <c>FromSendNotificationNode</c> consumer) performs the actual
///     send, exactly as it does for every other identity e-mail.
/// </summary>
/// <remarks>
///     The subject and body are composed in code (like <see cref="SignalRestOtpDeliveryChannel" />'s
///     message) rather than rendered from a <c>NotificationTemplate</c>: the OTP is an ad-hoc,
///     single-use message and the template store is seeded by a different service's blueprint
///     (<c>System.Notification.Bootstrap</c>). Publishing straight onto the hub is the documented
///     "proper wiring" (see <see cref="LoggingOtpDeliveryChannel" />) and keeps this channel
///     self-contained, migration-safe, and free of a cross-service template dependency. The only
///     secret that leaves identity-services is the one-time code itself; it is never logged.
/// </remarks>
public sealed class NotificationEmailOtpDeliveryChannel(
    IDistributionEventHubService distributionEventHubService,
    ILogger<NotificationEmailOtpDeliveryChannel> logger) : IOtpDeliveryChannel
{
    public OtpDeliveryChannelKind Kind => OtpDeliveryChannelKind.Email;

    public async Task DeliverAsync(OtpDeliveryContext context, CancellationToken cancellationToken = default)
    {
        var subject = "Your OctoMesh verification code";
        var body = BuildBody(context);

        var request = new SendNotificationsRequest(context.TenantId);
        request.Notifications.Add(new DistNotificationDto(subject, body, context.Destination, null, null));

        // Never log the raw code at Information or above — only the destination and outcome. A publish
        // failure propagates so the OTP service never tells the user a code was sent when it was not.
        logger.LogInformation(
            "[{TenantId}] AB#5123 sending e-mail OTP to '{Destination}' (valid {TtlMinutes} min).",
            context.TenantId, context.Destination, (int)context.Ttl.TotalMinutes);

        await distributionEventHubService.PublishAsync(request, cancellationToken);
    }

    private static string BuildBody(OtpDeliveryContext context)
    {
        var minutes = Math.Max(1, (int)Math.Round(context.Ttl.TotalMinutes));
        var greeting = string.IsNullOrWhiteSpace(context.UserName) ? "Hello," : $"Hello {context.UserName},";
        return $"{greeting}\n\n" +
               $"your OctoMesh verification code is {context.Code}.\n" +
               $"It is valid for {minutes} minute{(minutes == 1 ? string.Empty : "s")}.\n\n" +
               "If you did not request it, you can ignore this message.\n\n" +
               "OctoMesh Identity Services";
    }
}
