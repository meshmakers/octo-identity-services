using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>The outcome of setting the preferred outbound channel binding (AB#5149).</summary>
public enum SetPreferredChannelStatus
{
    /// <summary>The binding was accepted and its rtId stored on the user.</summary>
    Set = 0,

    /// <summary>The preference was cleared (null requested); always allowed.</summary>
    Cleared = 1,

    /// <summary>
    ///     The requested binding is not eligible: malformed id, not one of the user's own bindings,
    ///     not valid (expired), or of a kind no outbound channel exists for. Nothing was stored.
    /// </summary>
    BindingNotEligible = 2
}

/// <summary>
///     A binding the user may choose as their preferred outbound channel target: one of their own
///     VALID verified bindings whose identifier kind maps to an outbound channel
///     (PhoneNumber ⇒ SIGNAL, EntraIdObjectId ⇒ TEAMS).
/// </summary>
/// <param name="BindingId">The rtId of the VerifiedExternalIdentifier.</param>
/// <param name="Channel">The canonical channel name derived from the binding's kind ("TEAMS" | "SIGNAL").</param>
/// <param name="IdentifierValue">The binding's identifier value, for display (phone number / object id).</param>
public sealed record PreferredChannelOption(
    OctoObjectId BindingId,
    string Channel,
    string IdentifierValue);

/// <summary>
///     The user's current preferred-channel selection. All members are null while no (usable)
///     preference is set — including when the stored binding id has gone dangling because the
///     binding disappeared outside the self-service path.
/// </summary>
/// <param name="BindingId">The rtId of the chosen binding, or null.</param>
/// <param name="Channel">The canonical channel name derived from the chosen binding's kind, or null.</param>
/// <param name="IdentifierValue">The chosen binding's identifier value, or null.</param>
public sealed record PreferredChannelSelection(
    OctoObjectId? BindingId,
    string? Channel,
    string? IdentifierValue)
{
    public static readonly PreferredChannelSelection None = new(null, null, null);
}

/// <summary>Result of <see cref="IPreferredChannelService.SetPreferredChannelAsync" />.</summary>
/// <param name="Status">What happened.</param>
/// <param name="Selection">The effective selection after the call (never null; <see cref="PreferredChannelSelection.None" /> when unset).</param>
public sealed record SetPreferredChannelResult(
    SetPreferredChannelStatus Status,
    PreferredChannelSelection Selection);

/// <summary>
///     Per-user outbound channel preference (AB#5149, binding-specific revision): WHICH verified
///     binding the platform messages when it initiates contact (to-dos, document status,
///     notifications). Synchronous Q&amp;A answers keep replying on the channel the question came
///     from; only system-initiated routing reads this. The user stores the rtId of one of their own
///     valid VerifiedExternalIdentifier bindings (<c>RtUser.PreferredChannelBindingId</c>); the
///     channel KIND is derived from the referenced binding (PhoneNumber ⇒ SIGNAL, EntraIdObjectId ⇒
///     TEAMS), so a user with several phone numbers picks the concrete number. The attribute name
///     <c>PreferredChannelBindingId</c> is a cross-repo contract — the mesh adapter reads it from
///     the user entity and derives kind + target itself. Clearing (null) is always allowed, and
///     deleting the referenced binding clears the preference in the same operation.
/// </summary>
public interface IPreferredChannelService
{
    /// <summary>
    ///     The user's current selection, with channel kind and display value resolved from the
    ///     referenced binding. Returns <see cref="PreferredChannelSelection.None" /> when no
    ///     preference is set or the stored binding id is dangling.
    /// </summary>
    Task<PreferredChannelSelection> GetSelectionAsync(RtUser user);

    /// <summary>
    ///     The bindings the user may choose right now: every VALID binding of theirs whose kind maps
    ///     to an outbound channel, in enrollment order.
    /// </summary>
    Task<IReadOnlyList<PreferredChannelOption>> GetOptionsAsync(RtUser user);

    /// <summary>
    ///     Sets (or clears, when <paramref name="requestedBindingId" /> is null/blank) the user's
    ///     preferred outbound channel binding. The binding must be one of the user's own valid
    ///     bindings of a channel-mapped kind; anything else answers
    ///     <see cref="SetPreferredChannelStatus.BindingNotEligible" /> without touching the user.
    ///     Persists the user on success.
    /// </summary>
    Task<SetPreferredChannelResult> SetPreferredChannelAsync(RtUser user, string? requestedBindingId);

    /// <summary>
    ///     Clears the preference iff it currently references <paramref name="bindingId" />. Called by
    ///     the self-service deletion path so removing the preferred binding and clearing the
    ///     preference happen in the same operation. No-op otherwise.
    /// </summary>
    Task ClearIfReferencedAsync(RtUser user, OctoObjectId bindingId);
}
