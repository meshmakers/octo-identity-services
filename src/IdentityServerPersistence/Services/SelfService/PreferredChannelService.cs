using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     <see cref="IPreferredChannelService" /> over the AB#5122 verified-identifier directory and the
///     ASP.NET Identity user store. The binding gate reads
///     <see cref="IVerifiedIdentifierResolver.GetByUserAsync" /> and requires at least one VALID
///     binding of the channel's identifier kind — <c>IsValid</c> folds certificate/binding expiry in,
///     so an expired binding does not qualify. Persistence goes through
///     <see cref="UserManager{TUser}.UpdateAsync" /> (the same path every other user-profile scalar
///     takes), so the write lands on the tenant the request is scoped to.
/// </summary>
public class PreferredChannelService(
    IVerifiedIdentifierResolver verifiedIdentifierResolver,
    UserManager<RtUser> userManager,
    ILogger<PreferredChannelService> logger) : IPreferredChannelService
{
    /// <summary>
    ///     Canonical channel name → the identifier kind whose valid binding it requires. The uppercase
    ///     spellings are a cross-repo contract (mesh adapter WriteVerifiedCaller@1 emits them verbatim
    ///     as <c>preferredChannel</c>); extend here (e.g. <c>"EMAIL"</c> ⇒ EmailAddress) to add a channel.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, RtIdentifierKindEnum> ChannelBindingRequirements =
        new Dictionary<string, RtIdentifierKindEnum>(StringComparer.OrdinalIgnoreCase)
        {
            ["TEAMS"] = RtIdentifierKindEnum.EntraIdObjectId,
            ["SIGNAL"] = RtIdentifierKindEnum.PhoneNumber
        };

    /// <inheritdoc />
    public IReadOnlyList<string> SupportedChannels { get; } = ["TEAMS", "SIGNAL"];

    /// <inheritdoc />
    public async Task<SetPreferredChannelResult> SetPreferredChannelAsync(RtUser user, string? requestedChannel)
    {
        if (string.IsNullOrWhiteSpace(requestedChannel))
        {
            if (user.PreferredChannel != null)
            {
                user.PreferredChannel = null;
                await userManager.UpdateAsync(user);
                logger.LogInformation("User '{UserRtId}' cleared their preferred outbound channel", user.RtId);
            }

            return new SetPreferredChannelResult(SetPreferredChannelStatus.Cleared);
        }

        // Case-insensitive match, canonical (uppercase) storage — the stored value travels verbatim
        // into the verified-caller principal, so only the canonical spelling may ever be persisted.
        var canonical = SupportedChannels.FirstOrDefault(c =>
            string.Equals(c, requestedChannel.Trim(), StringComparison.OrdinalIgnoreCase));
        if (canonical == null)
        {
            return new SetPreferredChannelResult(SetPreferredChannelStatus.UnknownChannel, user.PreferredChannel);
        }

        var requiredKind = ChannelBindingRequirements[canonical];
        var identifiers = await verifiedIdentifierResolver.GetByUserAsync(user.RtId);
        if (!identifiers.Any(i => i.IdentifierKind == requiredKind && i.IsValid))
        {
            logger.LogInformation(
                "User '{UserRtId}' requested preferred channel '{Channel}' without a valid {Kind} binding; refused",
                user.RtId, canonical, requiredKind);
            return new SetPreferredChannelResult(SetPreferredChannelStatus.ChannelNotBound, user.PreferredChannel);
        }

        user.PreferredChannel = canonical;
        await userManager.UpdateAsync(user);
        logger.LogInformation("User '{UserRtId}' set their preferred outbound channel to '{Channel}'",
            user.RtId, canonical);
        return new SetPreferredChannelResult(SetPreferredChannelStatus.Set, canonical);
    }
}
