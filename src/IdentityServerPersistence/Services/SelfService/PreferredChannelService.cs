using System.Text.RegularExpressions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     <see cref="IPreferredChannelService" /> over the AB#5122 verified-identifier directory and the
///     ASP.NET Identity user store. Eligibility reads
///     <see cref="IVerifiedIdentifierResolver.GetByUserAsync" /> — the binding must be the user's OWN
///     and VALID (<c>IsValid</c> folds certificate/binding expiry in, so an expired binding does not
///     qualify) and of a kind that maps to an outbound channel. Persistence goes through
///     <see cref="UserManager{TUser}.UpdateAsync" /> (the same path every other user-profile scalar
///     takes), so the write lands on the tenant the request is scoped to.
/// </summary>
public partial class PreferredChannelService(
    IVerifiedIdentifierResolver verifiedIdentifierResolver,
    UserManager<RtUser> userManager,
    ILogger<PreferredChannelService> logger) : IPreferredChannelService
{
    /// <summary>
    ///     Identifier kind → the canonical outbound channel it carries. The uppercase spellings are a
    ///     cross-repo contract (the mesh adapter derives the same mapping from
    ///     <c>PreferredChannelBindingId</c>); extend here (e.g. EmailAddress ⇒ <c>"EMAIL"</c>) to add
    ///     a channel.
    /// </summary>
    private static readonly IReadOnlyDictionary<RtIdentifierKindEnum, string> KindToChannel =
        new Dictionary<RtIdentifierKindEnum, string>
        {
            [RtIdentifierKindEnum.EntraIdObjectId] = "TEAMS",
            [RtIdentifierKindEnum.PhoneNumber] = "SIGNAL"
        };

    /// <inheritdoc />
    public async Task<PreferredChannelSelection> GetSelectionAsync(RtUser user)
    {
        if (string.IsNullOrWhiteSpace(user.PreferredChannelBindingId))
        {
            return PreferredChannelSelection.None;
        }

        var options = await GetOptionsAsync(user);
        var selected = options.FirstOrDefault(o => o.BindingId.ToString() == user.PreferredChannelBindingId);
        if (selected == null)
        {
            // Dangling or no-longer-eligible reference (binding removed outside the self-service
            // path, or expired). Reads never write — the stale id stays until the user re-selects
            // or clears; consumers see "no preference".
            return PreferredChannelSelection.None;
        }

        return new PreferredChannelSelection(selected.BindingId, selected.Channel, selected.IdentifierValue);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<PreferredChannelOption>> GetOptionsAsync(RtUser user)
    {
        var identifiers = await verifiedIdentifierResolver.GetByUserAsync(user.RtId);
        return identifiers
            .Where(i => i.IsValid && KindToChannel.ContainsKey(i.IdentifierKind))
            .Select(i => new PreferredChannelOption(i.RtId, KindToChannel[i.IdentifierKind], i.IdentifierValue))
            .ToList();
    }

    /// <inheritdoc />
    public async Task<SetPreferredChannelResult> SetPreferredChannelAsync(RtUser user, string? requestedBindingId)
    {
        if (string.IsNullOrWhiteSpace(requestedBindingId))
        {
            if (user.PreferredChannelBindingId != null)
            {
                user.PreferredChannelBindingId = null;
                await userManager.UpdateAsync(user);
                logger.LogInformation("User '{UserRtId}' cleared their preferred outbound channel binding",
                    user.RtId);
            }

            return new SetPreferredChannelResult(SetPreferredChannelStatus.Cleared,
                PreferredChannelSelection.None);
        }

        var trimmed = requestedBindingId.Trim();
        if (!RtIdRegex().IsMatch(trimmed))
        {
            logger.LogInformation(
                "User '{UserRtId}' requested a malformed preferred channel binding id; refused", user.RtId);
            return new SetPreferredChannelResult(SetPreferredChannelStatus.BindingNotEligible,
                await GetSelectionAsync(user));
        }

        // Eligibility = "is one of the options": the user's OWN binding, valid, of a channel-mapped
        // kind. A foreign or unknown binding id is indistinguishable from an ineligible one by
        // design — the answer never leaks whether the id exists.
        var options = await GetOptionsAsync(user);
        var chosen = options.FirstOrDefault(o => o.BindingId.ToString() == trimmed);
        if (chosen == null)
        {
            logger.LogInformation(
                "User '{UserRtId}' requested preferred channel binding '{BindingId}' which is not one of their eligible bindings; refused",
                user.RtId, trimmed);
            return new SetPreferredChannelResult(SetPreferredChannelStatus.BindingNotEligible,
                await GetSelectionAsync(user));
        }

        user.PreferredChannelBindingId = chosen.BindingId.ToString();
        await userManager.UpdateAsync(user);
        logger.LogInformation(
            "User '{UserRtId}' set their preferred outbound channel binding to '{BindingId}' ({Channel})",
            user.RtId, chosen.BindingId, chosen.Channel);
        return new SetPreferredChannelResult(SetPreferredChannelStatus.Set,
            new PreferredChannelSelection(chosen.BindingId, chosen.Channel, chosen.IdentifierValue));
    }

    /// <inheritdoc />
    public async Task ClearIfReferencedAsync(RtUser user, OctoObjectId bindingId)
    {
        if (user.PreferredChannelBindingId != bindingId.ToString())
        {
            return;
        }

        user.PreferredChannelBindingId = null;
        await userManager.UpdateAsync(user);
        logger.LogInformation(
            "Cleared user '{UserRtId}' preferred outbound channel because its binding '{BindingId}' was removed",
            user.RtId, bindingId);
    }

    [GeneratedRegex("^[0-9a-fA-F]{24}$")]
    private static partial Regex RtIdRegex();
}
