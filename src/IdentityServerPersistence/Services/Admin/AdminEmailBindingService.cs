using System.Net.Mail;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Admin;

/// <inheritdoc />
public sealed class AdminEmailBindingService(
    IVerifiedIdentifierResolver verifiedIdentifierResolver,
    ILogger<AdminEmailBindingService> logger) : IAdminEmailBindingService
{
    public async Task<IReadOnlyList<VerifiedIdentifierWithUser>> ListAsync()
        => await verifiedIdentifierResolver.GetByKindAsync(RtIdentifierKindEnum.EmailAddress);

    public async Task<AdminBindEmailResult> BindEmailAsync(OctoObjectId userRtId, string rawEmail)
    {
        if (!TryNormalizeEmail(rawEmail, out var normalized))
        {
            return new AdminBindEmailResult(AdminBindEmailStatus.InvalidEmail);
        }

        try
        {
            var bindingRtId = await verifiedIdentifierResolver.StoreBindingAsync(new VerifiedIdentifierBinding(
                RtIdentifierKindEnum.EmailAddress,
                normalized,
                userRtId,
                // ENROLLMENT dimension: admin-verified whitelist ⇒ Strong. The per-message dimension
                // (DKIM/DMARC) is evaluated on ingest and capped by min() at the directory.
                RtTrustLevelEnum.Strong,
                RtIdentifierSourceEnum.Admin,
                // The channel is expected to authenticate every message (valid DKIM/DMARC) before the
                // address may be trusted for an elevated operation — documents the binding's intent.
                RequiredMessageAuthentication: true,
                LastVerifiedAt: DateTime.UtcNow));

            logger.LogInformation(
                "Admin bound e-mail address to user '{UserRtId}' as Strong/Admin (binding {BindingRtId})",
                userRtId, bindingRtId);

            return new AdminBindEmailResult(AdminBindEmailStatus.Bound, normalized, bindingRtId);
        }
        catch (NotExistingException)
        {
            // The resolver rejects a binding to a phantom identity — surface it as a clean status.
            logger.LogWarning("Admin e-mail binding refused: user '{UserRtId}' does not exist", userRtId);
            return new AdminBindEmailResult(AdminBindEmailStatus.UserNotFound, normalized);
        }
    }

    public async Task<bool> RemoveAsync(string rawEmail)
    {
        // A remove normalizes the same way as the write so it targets the row the write created; an
        // unparseable address simply matches nothing.
        if (!TryNormalizeEmail(rawEmail, out var normalized))
        {
            return false;
        }

        return await verifiedIdentifierResolver.RemoveBindingAsync(RtIdentifierKindEnum.EmailAddress, normalized);
    }

    /// <summary>
    ///     Trims and lower-cases the address and requires it to be a bare, valid e-mail — no display
    ///     name, no angle brackets, no list of addresses. Kept identical to the adapter's e-mail
    ///     lookup normalization so the stored value and the inbound From match case-insensitively.
    /// </summary>
    private static bool TryNormalizeEmail(string? raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var candidate = raw.Trim().ToLowerInvariant();

        // MailAddress accepts "Name <a@b.com>"; require the parsed address to equal the input so only
        // a bare address passes.
        if (!MailAddress.TryCreate(candidate, out var address) ||
            !string.Equals(address.Address, candidate, StringComparison.Ordinal))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }
}
