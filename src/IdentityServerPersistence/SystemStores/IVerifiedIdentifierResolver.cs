using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

/// <summary>
///     The input to <see cref="IVerifiedIdentifierResolver.StoreBindingAsync" />: everything the
///     directory needs to record a verified (external identifier → user) binding (AB#5122). This is
///     the write-side SEAM the sibling enrollment WIs (AB#5123–5126) call once they have proven
///     ownership of the identifier; this WI carries no enrollment/OTP/cert logic of its own.
/// </summary>
/// <param name="IdentifierKind">The kind of identifier (phone / e-mail / EntraID oid / cert fingerprint).</param>
/// <param name="IdentifierValue">The normalized identifier value. Uniqueness is per (kind, value) within the tenant.</param>
/// <param name="UserRtId">The OctoMesh user the identifier belongs to. Rejected if the user does not exist.</param>
/// <param name="EnrollmentTrust">The stored enrollment-trust dimension the enrollment WI proved (None/Weak/Strong).</param>
/// <param name="Source">Provenance of the binding (SelfService / Admin / IdentityProvider).</param>
/// <param name="RequiredMessageAuthentication">Channel expectation for the per-message dimension (documented, not part of the min).</param>
/// <param name="EnrolledAt">First-enrollment timestamp; defaults to now on first insert, preserved on update.</param>
/// <param name="LastVerifiedAt">Most-recent-verification timestamp; defaults to now when omitted.</param>
public sealed record VerifiedIdentifierBinding(
    RtIdentifierKindEnum IdentifierKind,
    string IdentifierValue,
    OctoObjectId UserRtId,
    RtTrustLevelEnum EnrollmentTrust,
    RtIdentifierSourceEnum Source,
    bool RequiredMessageAuthentication = false,
    DateTime? EnrolledAt = null,
    DateTime? LastVerifiedAt = null,
    DateTime? ValidUntil = null);

/// <summary>
///     A read-only projection of a single <c>VerifiedExternalIdentifier</c> owned by a user, for the
///     self-service "My identities" listing (AB#5123). <see cref="IsValid" /> already folds in
///     certificate expiry (a <see cref="ValidUntil" /> in the past means the binding is invalid).
/// </summary>
public sealed record VerifiedIdentifierSummary(
    OctoObjectId RtId,
    RtIdentifierKindEnum IdentifierKind,
    string IdentifierValue,
    RtTrustLevelEnum EnrollmentTrust,
    RtIdentifierSourceEnum Source,
    DateTime? EnrolledAt,
    DateTime? LastVerifiedAt,
    DateTime? ValidUntil,
    bool IsValid);

/// <summary>
///     A single binding of a given kind together with the user it points at, for the admin
///     "verified whitelist" listing (AB#5125): the admin manages the tenant's e-mail→user bindings
///     and needs to see which user each address maps to, not just the address. The user projection is
///     resolved from the <c>IdentifiesUser</c> edge; <see cref="UserRtId" /> is the empty id when the
///     binding is dangling (its user was removed).
/// </summary>
public sealed record VerifiedIdentifierWithUser(
    VerifiedIdentifierSummary Identifier,
    OctoObjectId UserRtId,
    string? UserName,
    string? UserEmail);

/// <summary>
///     The outcome of <see cref="IVerifiedIdentifierResolver.ResolveAsync" /> for a present binding:
///     the resolved user together with both trust dimensions and their effective minimum (AB#5122).
/// </summary>
/// <param name="User">The OctoMesh user the identifier resolves to.</param>
/// <param name="BindingRtId">RtId of the <c>VerifiedExternalIdentifier</c> that matched.</param>
/// <param name="EnrollmentTrust">The stored enrollment-trust dimension of the binding.</param>
/// <param name="MessageTrust">The per-call message-trust dimension handed to the resolver.</param>
/// <param name="EffectiveTrust"><c>min(EnrollmentTrust, MessageTrust)</c> — the trust callers must act on.</param>
public sealed record VerifiedIdentifierResolution(
    RtUser User,
    OctoObjectId BindingRtId,
    RtTrustLevelEnum EnrollmentTrust,
    RtTrustLevelEnum MessageTrust,
    RtTrustLevelEnum EffectiveTrust);

/// <summary>
///     The verified external identifier directory (AB#5122, Epic AB#4979): resolves a verified
///     external identifier (phone number, e-mail address, EntraID object id, client certificate
///     fingerprint) to an OctoMesh user, carrying two INDEPENDENT trust dimensions whose minimum is
///     the effective trust.
/// </summary>
/// <remarks>
///     <para>
///         The two dimensions are modeled asymmetrically on purpose. The ENROLLMENT trust ("does the
///         identifier belong to the user?") is a stable property of the binding and is stored on the
///         <c>VerifiedExternalIdentifier</c> entity. The per-MESSAGE trust ("is THIS message really
///         from that identifier?" — Signal protocol / DKIM validity) depends on the incoming message
///         and is therefore NOT stored: it is passed to <see cref="ResolveAsync" /> per call and the
///         resolver returns <c>effective = min(enrollment, message)</c>. Nothing is stored that
///         couples the directory to a single channel.
///     </para>
///     <para>
///         This WI provides only the shared CK model and this resolver. Channel wiring, UI, and the
///         OTP / certificate / IdP enrollment flows are sibling WIs (AB#5123–5126); the write side
///         (<see cref="StoreBindingAsync" /> / <see cref="RemoveBindingAsync" />) is the seam they
///         call.
///     </para>
/// </remarks>
public interface IVerifiedIdentifierResolver
{
    /// <summary>
    ///     Resolves <paramref name="identifierKind" />/<paramref name="identifierValue" /> to its
    ///     bound user and the effective trust for a message that arrived with
    ///     <paramref name="messageTrust" />. Returns <c>null</c> when no binding exists (or the
    ///     binding is dangling because its user was removed).
    /// </summary>
    Task<VerifiedIdentifierResolution?> ResolveAsync(
        RtIdentifierKindEnum identifierKind,
        string identifierValue,
        RtTrustLevelEnum messageTrust);

    /// <summary>
    ///     Creates or updates (upserts) the binding for its (kind, value) — additive and idempotent.
    ///     Enforces the directory invariant that a (kind, value) resolves to at most one user within
    ///     the tenant: the single row is updated in place, re-pointing the user association when it
    ///     changed. Rejects an unknown <see cref="VerifiedIdentifierBinding.UserRtId" /> with
    ///     <see cref="NotExistingException" />. Returns the RtId of the affected binding.
    /// </summary>
    Task<OctoObjectId> StoreBindingAsync(VerifiedIdentifierBinding binding);

    /// <summary>
    ///     Removes the binding for the given (kind, value). Idempotent: a no-op when absent. Returns
    ///     <c>true</c> when a binding was removed.
    /// </summary>
    Task<bool> RemoveBindingAsync(RtIdentifierKindEnum identifierKind, string identifierValue);

    /// <summary>
    ///     Lists every verified identifier bound to <paramref name="userRtId" /> — the read side of
    ///     the self-service "My identities" area (AB#5123). Each summary already reflects certificate
    ///     expiry in its <see cref="VerifiedIdentifierSummary.IsValid" /> flag.
    /// </summary>
    Task<IReadOnlyList<VerifiedIdentifierSummary>> GetByUserAsync(OctoObjectId userRtId);

    /// <summary>
    ///     Lists every binding of <paramref name="identifierKind" /> in the tenant, each with the user
    ///     it points at — the read side of the admin "verified whitelist" area (AB#5125), which manages
    ///     the tenant's e-mail→user bindings. Each summary already reflects certificate expiry in its
    ///     <see cref="VerifiedIdentifierSummary.IsValid" /> flag.
    /// </summary>
    Task<IReadOnlyList<VerifiedIdentifierWithUser>> GetByKindAsync(RtIdentifierKindEnum identifierKind);
}
