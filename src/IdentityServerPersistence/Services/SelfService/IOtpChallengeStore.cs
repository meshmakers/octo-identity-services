using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     A pending OTP challenge for one (user, destination) (AB#5123). The code itself is NEVER stored:
///     only a salted hash is, so a leak of the challenge store cannot reveal the code. Expiry and the
///     attempt counter live here too, so a wrong or expired code can never enroll.
/// </summary>
/// <param name="Destination">The normalized identifier the code was sent to (E.164 phone number).</param>
/// <param name="CodeHash">Base64 SHA-256 of <see cref="Salt" /> ++ code — the only trace of the code.</param>
/// <param name="Salt">Base64 per-challenge random salt.</param>
/// <param name="ExpiresAtUtc">UTC instant after which the challenge is dead regardless of attempts.</param>
/// <param name="Attempts">How many verify attempts have already been consumed.</param>
/// <param name="MaxAttempts">The attempt ceiling; the challenge is burned once it is reached.</param>
public sealed record OtpChallenge(
    string Destination,
    string CodeHash,
    string Salt,
    DateTime ExpiresAtUtc,
    int Attempts,
    int MaxAttempts);

/// <summary>
///     Durable, per-user persistence for the pending OTP challenge (AB#5123). One challenge per
///     (user, destination); starting a new enrollment for the same destination replaces the previous
///     one. Kept behind this seam so the OTP verification logic can be unit-tested without a store.
/// </summary>
public interface IOtpChallengeStore
{
    /// <summary>Upserts (replaces) the pending challenge for <paramref name="user" /> + destination.</summary>
    Task StoreAsync(RtUser user, OtpChallenge challenge);

    /// <summary>Returns the pending challenge for the (user, destination), or <c>null</c> when none.</summary>
    Task<OtpChallenge?> GetAsync(RtUser user, string destination);

    /// <summary>Removes the pending challenge for the (user, destination). Idempotent.</summary>
    Task RemoveAsync(RtUser user, string destination);
}
