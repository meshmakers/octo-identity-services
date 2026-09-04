using Microsoft.Extensions.Logging;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     🔴 <b>PLUGGABLE STUB — NOT FOR PRODUCTION (AB#5123).</b> The phone-OTP delivery transport
///     (Signal / SMS) that identity-services would use does not exist as a service it can reach:
///     the only outbound messaging identity-services has is the e-mail notification service
///     (<c>INotificationService</c>), and the Signal SEND path lives in the mesh adapter
///     (<c>SignalSenderNode</c>), driven by pipelines, with no cross-service send API. Rather than
///     integrate a new external SMS provider SDK (explicitly out of scope), this stub stands in for
///     the phone modality: it writes the code to the log so the flow is exercisable end-to-end in
///     dev, and is the single class a real Signal/SMS channel replaces (register the real
///     <see cref="IOtpDeliveryChannel" /> for <see cref="OtpDeliveryChannelKind.Signal" /> /
///     <see cref="OtpDeliveryChannelKind.Sms" /> and drop this).
/// </summary>
/// <remarks>
///     The proper wiring, when the transport exists, is to publish a Signal notification onto the
///     distribution event hub (the same seam <c>NotificationService</c> uses for e-mail) so the
///     tenant's Signal adapter delivers it — no secret ever leaves the identity service except the
///     one-time code, exactly as here.
/// </remarks>
public sealed class LoggingOtpDeliveryChannel(ILogger<LoggingOtpDeliveryChannel> logger)
    : IOtpDeliveryChannel
{
    public OtpDeliveryChannelKind Kind => OtpDeliveryChannelKind.Signal;

    public Task DeliverAsync(OtpDeliveryContext context, CancellationToken cancellationToken = default)
    {
        // Warning level on purpose: a real deployment must never rely on this — the code appearing in
        // the log is the whole point of the stub and also the reason it must not ship enabled.
        logger.LogWarning(
            "[{TenantId}] AB#5123 OTP DELIVERY STUB: would send one-time code '{Code}' to '{Destination}' " +
            "(valid {TtlMinutes} min). No real Signal/SMS transport is wired — replace LoggingOtpDeliveryChannel " +
            "with a real IOtpDeliveryChannel before production.",
            context.TenantId, context.Code, context.Destination, (int)context.Ttl.TotalMinutes);

        return Task.CompletedTask;
    }
}
