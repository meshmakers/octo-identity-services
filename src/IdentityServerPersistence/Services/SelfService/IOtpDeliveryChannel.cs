namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     The transport an OTP is delivered over (AB#5123). Kept channel-neutral so the self-service
///     OTP service picks a delivery by modality and a future channel (a real Signal/SMS transport,
///     AB#5125 e-mail) slots in as another <see cref="IOtpDeliveryChannel" /> without touching the
///     verification logic.
/// </summary>
public enum OtpDeliveryChannelKind
{
    /// <summary>Signal message to a phone number — the preferred phone-OTP transport (AB#5123).</summary>
    Signal = 0,

    /// <summary>SMS to a phone number.</summary>
    Sms = 1,

    /// <summary>E-mail to an address (reuses the identity notification service).</summary>
    Email = 2
}

/// <summary>
///     Everything a delivery channel needs to send one OTP (AB#5123). Carries no secret beyond the
///     one-time <see cref="Code" />, which is never persisted in the clear (the challenge stores only
///     a salted hash).
/// </summary>
/// <param name="TenantId">The tenant the enrolling user belongs to.</param>
/// <param name="Destination">The normalized identifier the code is sent to (E.164 phone / e-mail).</param>
/// <param name="Code">The one-time code, in the clear, for this single delivery.</param>
/// <param name="Ttl">How long the code stays valid — for the message text.</param>
/// <param name="UserName">The enrolling user's display name, for the message text.</param>
public sealed record OtpDeliveryContext(
    string TenantId,
    string Destination,
    string Code,
    TimeSpan Ttl,
    string? UserName);

/// <summary>
///     A single OTP delivery transport (AB#5123). The self-service OTP service holds every registered
///     channel and dispatches to the first one whose <see cref="Kind" /> matches the modality it wants
///     for an identifier — the same kind-dispatch shape the adapter's verified-caller directory uses.
/// </summary>
public interface IOtpDeliveryChannel
{
    /// <summary>The modality this channel delivers.</summary>
    OtpDeliveryChannelKind Kind { get; }

    /// <summary>
    ///     Delivers <paramref name="context" />'s code to its destination. Throws when delivery could
    ///     not be attempted, so the OTP service does not tell the user a code was sent when it was not.
    /// </summary>
    Task DeliverAsync(OtpDeliveryContext context, CancellationToken cancellationToken = default);
}
