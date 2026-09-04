using System.Security.Claims;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Login;

/// <summary>
///     Auto-provisions the AB#5122 verified-identifier binding <c>(EntraIdObjectId, oid) → user</c>
///     when a user logs in through an <b>EntraID</b> identity provider (AB#5124, "Strang B" of the
///     pipeline-identity epic AB#4979). This is what makes the Teams caller-identity resolution
///     "almost free": a Teams message carries the sender's AAD object id, and this binding lets the
///     mesh adapter resolve that oid straight to the OctoMesh user the IdP already provisioned — no
///     separate enrollment step.
/// </summary>
/// <remarks>
///     Called on every EntraID login, right next to the group-claim sync. It is additive and
///     idempotent (the resolver upserts the single row for the oid) and best-effort: an enrollment
///     failure is logged, never propagated, so it can never block a login. For any non-EntraID
///     provider, or a token without an <c>oid</c> claim, it is a no-op.
/// </remarks>
public interface IEntraIdVerifiedIdentifierEnrollmentService
{
    /// <summary>
    ///     Enrolls the EntraID object id from <paramref name="externalClaims" /> for
    ///     <paramref name="user" /> when <paramref name="providerName" /> is an
    ///     <see cref="RtAzureEntraIdIdentityProvider" />. No-op otherwise.
    /// </summary>
    /// <param name="user">The OctoMesh user resolved/created for the external login.</param>
    /// <param name="providerName">The identity-provider scheme name the login came through (may be scheme-prefixed).</param>
    /// <param name="externalClaims">The external principal's claims (source of the <c>oid</c>).</param>
    Task EnrollFromExternalLoginAsync(RtUser user, string providerName, IReadOnlyList<Claim> externalClaims);
}
