using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>The outcome of starting a phone enrollment (AB#5123).</summary>
public enum StartPhoneEnrollmentStatus
{
    /// <summary>A code was generated, stored (hashed) and handed to a delivery channel.</summary>
    CodeSent = 0,

    /// <summary>The supplied number could not be normalized to an E.164 phone number.</summary>
    InvalidNumber = 1,

    /// <summary>The number is already a verified identifier of ANOTHER user; self-service refuses it.</summary>
    AlreadyOwnedByAnotherUser = 2
}

/// <summary>The outcome of verifying an OTP (AB#5123). Only <see cref="Verified" /> enrolls.</summary>
public enum OtpVerificationStatus
{
    /// <summary>Code matched an unexpired, in-budget challenge; the identifier was enrolled Strong.</summary>
    Verified = 0,

    /// <summary>No pending challenge for this (user, number) — nothing was sent or it was consumed.</summary>
    NoChallenge = 1,

    /// <summary>The challenge existed but its expiry has passed; it was discarded, nothing enrolled.</summary>
    Expired = 2,

    /// <summary>The attempt ceiling was already reached; the challenge was burned, nothing enrolled.</summary>
    AttemptLimitReached = 3,

    /// <summary>The code did not match; an attempt was consumed, nothing enrolled.</summary>
    CodeMismatch = 4,

    /// <summary>The number became a verified identifier of another user meanwhile; nothing enrolled.</summary>
    AlreadyOwnedByAnotherUser = 5,

    /// <summary>The number could not be normalized; nothing enrolled.</summary>
    InvalidNumber = 6
}

/// <summary>Result of <see cref="ISelfServiceIdentifierService.StartPhoneEnrollmentAsync" />.</summary>
/// <param name="Status">What happened.</param>
/// <param name="NormalizedNumber">The E.164 number, when it normalized.</param>
/// <param name="MaskedDestination">A privacy-masked form of the number for the UI, when sent.</param>
/// <param name="ExpiresAtUtc">When the code stops being valid, when sent.</param>
public sealed record StartPhoneEnrollmentResult(
    StartPhoneEnrollmentStatus Status,
    string? NormalizedNumber = null,
    string? MaskedDestination = null,
    DateTime? ExpiresAtUtc = null);

/// <summary>Result of <see cref="ISelfServiceIdentifierService.VerifyPhoneAsync" />.</summary>
/// <param name="Status">What happened.</param>
/// <param name="AttemptsRemaining">Verify attempts left for the challenge (0 once burned).</param>
/// <param name="BindingRtId">The enrolled binding's RtId, on success.</param>
public sealed record OtpVerificationResult(
    OtpVerificationStatus Status,
    int AttemptsRemaining = 0,
    OctoObjectId? BindingRtId = null);

/// <summary>The outcome of enrolling a client certificate (AB#5123).</summary>
public enum CertificateEnrollmentStatus
{
    /// <summary>The certificate parsed, was valid, and its fingerprint was enrolled Strong.</summary>
    Enrolled = 0,

    /// <summary>The uploaded bytes could not be parsed as an X.509 certificate.</summary>
    Unreadable = 1,

    /// <summary>The certificate's validity window does not include now (expired or not yet valid).</summary>
    NotValid = 2,

    /// <summary>The fingerprint is already a verified identifier of another user; refused.</summary>
    AlreadyOwnedByAnotherUser = 3
}

/// <summary>Result of <see cref="ISelfServiceIdentifierService.EnrollCertificateAsync" />.</summary>
/// <param name="Status">What happened.</param>
/// <param name="Fingerprint">The SHA-256 fingerprint, when the certificate parsed.</param>
/// <param name="ValidUntilUtc">The certificate not-after, when the certificate parsed.</param>
/// <param name="BindingRtId">The enrolled binding's RtId, on success.</param>
public sealed record CertificateEnrollmentResult(
    CertificateEnrollmentStatus Status,
    string? Fingerprint = null,
    DateTime? ValidUntilUtc = null,
    OctoObjectId? BindingRtId = null);

/// <summary>
///     The self-service verified-identifier area (AB#5123, "Strang B" of Epic AB#4979): lets the
///     signed-in user manage their OWN strong channel identifiers — phone numbers (OTP-verified) and
///     client certificates — with no admin in the loop. Every write goes through the AB#5122
///     <see cref="IVerifiedIdentifierResolver" /> with <c>Source = SelfService</c> and, on proven
///     ownership, <c>EnrollmentTrust = Strong</c>, and ALWAYS maps to the enrolling user's own
///     identity: an identifier already owned by another user is refused, never re-pointed.
/// </summary>
public interface ISelfServiceIdentifierService
{
    /// <summary>Lists the user's own verified identifiers (certificate validity already folded in).</summary>
    Task<IReadOnlyList<VerifiedIdentifierSummary>> ListAsync(RtUser user);

    /// <summary>
    ///     Starts a phone enrollment: normalizes the number, generates a one-time code, stores only
    ///     its salted hash with an expiry and a fresh attempt budget, and hands the code to a delivery
    ///     channel. No binding is written here — enrollment happens only on a correct
    ///     <see cref="VerifyPhoneAsync" />.
    /// </summary>
    Task<StartPhoneEnrollmentResult> StartPhoneEnrollmentAsync(string tenantId, RtUser user,
        string rawPhoneNumber, CancellationToken cancellationToken = default);

    /// <summary>
    ///     Verifies an OTP against the pending challenge for the (user, number). A wrong, expired, or
    ///     over-budget code NEVER enrolls; only a correct, unexpired, in-budget code stores the
    ///     <c>VerifiedExternalIdentifier(PhoneNumber, Strong, SelfService)</c> binding.
    /// </summary>
    Task<OtpVerificationResult> VerifyPhoneAsync(string tenantId, RtUser user, string rawPhoneNumber,
        string code);

    /// <summary>
    ///     Enrolls a client certificate as a Strong self-service identifier: parses it, checks its
    ///     validity window, stores its SHA-256 fingerprint and not-after. An expired / not-yet-valid
    ///     certificate is refused (and a stored one whose not-after passes later drops to invalid).
    /// </summary>
    Task<CertificateEnrollmentResult> EnrollCertificateAsync(string tenantId, RtUser user,
        byte[] certificateBytes);

    /// <summary>
    ///     Removes one of the user's OWN verified identifiers. Refuses (returns <c>false</c>) when the
    ///     (kind, value) is not owned by <paramref name="user" />, so a user can only ever remove their
    ///     own identifiers.
    /// </summary>
    Task<bool> RemoveAsync(RtUser user, RtIdentifierKindEnum identifierKind, string identifierValue);
}
