using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence.Services.Admin;

/// <summary>The outcome of an admin binding an e-mail address to a user (AB#5125).</summary>
public enum AdminBindEmailStatus
{
    /// <summary>The address was bound (created or re-pointed) to the user, enrollment Strong.</summary>
    Bound = 0,

    /// <summary>The supplied text is not a bare, valid e-mail address; nothing was written.</summary>
    InvalidEmail = 1,

    /// <summary>No user exists for the supplied id; nothing was written.</summary>
    UserNotFound = 2
}

/// <summary>Result of <see cref="IAdminEmailBindingService.BindEmailAsync" />.</summary>
/// <param name="Status">What happened.</param>
/// <param name="NormalizedEmail">The trimmed, lower-cased address that was (or would be) stored.</param>
/// <param name="BindingRtId">The affected binding's RtId, on success.</param>
public sealed record AdminBindEmailResult(
    AdminBindEmailStatus Status,
    string? NormalizedEmail = null,
    OctoObjectId? BindingRtId = null);

/// <summary>
///     The admin-managed e-mail verified-whitelist (AB#5125, "Strang B" of Epic AB#4979): a tenant
///     admin binds an e-mail address to an OctoMesh user without the user in the loop. Every write
///     goes through the AB#5122 <see cref="IVerifiedIdentifierResolver" /> with
///     <c>Source = Admin</c> and <c>EnrollmentTrust = Strong</c> — the ENROLLMENT dimension only.
/// </summary>
/// <remarks>
///     🔴 <b>Strong enrollment is not strong authorization.</b> A whitelisted address is proven to
///     BELONG to the user, but any given inbound mail is only as trustworthy as its DKIM/DMARC verdict
///     (the SMTP From is spoofable). The per-message trust is evaluated on the ingest side and the
///     verified-caller directory takes <c>effective = min(enrollment, message)</c>, so a message
///     without valid DKIM/DMARC never authorizes an elevated operation even from a whitelisted
///     address. This service therefore also sets <c>RequiredMessageAuthentication = true</c> to record
///     that the channel is expected to authenticate every message.
/// </remarks>
public interface IAdminEmailBindingService
{
    /// <summary>Lists every admin/self-service e-mail binding in the tenant, each with its user.</summary>
    Task<IReadOnlyList<VerifiedIdentifierWithUser>> ListAsync();

    /// <summary>
    ///     Binds (upserts) <paramref name="rawEmail" /> to <paramref name="userRtId" /> as a Strong,
    ///     Admin-sourced verified identifier. Validates and normalizes the address; refuses an unknown
    ///     user. Idempotent for the (kind, value): an existing binding is re-pointed to the user.
    /// </summary>
    Task<AdminBindEmailResult> BindEmailAsync(OctoObjectId userRtId, string rawEmail);

    /// <summary>Removes the e-mail binding for <paramref name="rawEmail" />. Idempotent; true when one was removed.</summary>
    Task<bool> RemoveAsync(string rawEmail);
}
