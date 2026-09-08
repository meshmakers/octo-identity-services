using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>The outcome of setting the preferred outbound channel (AB#5149).</summary>
public enum SetPreferredChannelStatus
{
    /// <summary>The channel was accepted and stored on the user.</summary>
    Set = 0,

    /// <summary>The preference was cleared (null requested); always allowed.</summary>
    Cleared = 1,

    /// <summary>The requested channel is not a supported channel name.</summary>
    UnknownChannel = 2,

    /// <summary>The user holds no valid verified binding for the channel; nothing was stored.</summary>
    ChannelNotBound = 3
}

/// <summary>Result of <see cref="IPreferredChannelService.SetPreferredChannelAsync" />.</summary>
/// <param name="Status">What happened.</param>
/// <param name="PreferredChannel">The canonical stored value after the call (null when cleared or refused while unset).</param>
public sealed record SetPreferredChannelResult(
    SetPreferredChannelStatus Status,
    string? PreferredChannel = null);

/// <summary>
///     Per-user outbound channel preference (AB#5149): which channel the platform uses for
///     system-initiated messages (to-dos, document status, notifications). Synchronous Q&amp;A answers
///     keep replying on the channel the question came from; only system-initiated routing reads this.
///     The value is stored on the user (<c>RtUser.PreferredChannel</c>) as a canonical uppercase
///     channel name and is propagated verbatim into the mesh adapter's verified-caller principal, so
///     the exact spellings are a cross-repo contract: <c>"TEAMS"</c> and <c>"SIGNAL"</c> (extensible,
///     e.g. <c>"EMAIL"</c> later). A channel may only be chosen while the user holds a VALID verified
///     binding of the channel's identifier kind (TEAMS ⇒ EntraIdObjectId, SIGNAL ⇒ PhoneNumber) —
///     otherwise the system would route messages into a channel that cannot reach the user. Clearing
///     (null) is always allowed.
/// </summary>
public interface IPreferredChannelService
{
    /// <summary>
    ///     The canonical channel names self-service accepts, in display order. The controller uses it
    ///     for error texts; the binding requirement per channel is internal to the implementation.
    /// </summary>
    IReadOnlyList<string> SupportedChannels { get; }

    /// <summary>
    ///     Sets (or clears, when <paramref name="requestedChannel" /> is null/blank) the user's
    ///     preferred outbound channel. Channel names are matched case-insensitively and stored in
    ///     their canonical uppercase spelling. Persists the user on success.
    /// </summary>
    Task<SetPreferredChannelResult> SetPreferredChannelAsync(RtUser user, string? requestedChannel);
}
