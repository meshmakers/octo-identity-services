using Microsoft.Extensions.Caching.Memory;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Makes the cross-tenant two-factor challenge cookie single-use (AB#7861, review finding 5).
/// </summary>
/// <remarks>
///     The challenge (<c>.AspNetCore.Octo.CrossTenantTwoFactor</c>) is a data-protected, time-limited cookie (5 minutes)
///     that says "the password of the source user was verified for this tenant". Deleting it in the browser after a
///     success, a lockout or a logout does not invalidate a copy. Each challenge therefore carries a nonce, and the nonce
///     is marked used here for the rest of the cookie lifetime. The marker is kept in process memory: with several
///     identity pods a copy could still be replayed once on another pod within the 5 minutes — it would still need a
///     valid second-factor code of the source user, so this is a hardening, not the security boundary.
/// </remarks>
public interface ICrossTenantChallengeReplayGuard
{
    /// <summary>Whether the challenge with <paramref name="nonce" /> was already completed or cancelled.</summary>
    bool IsUsed(string nonce);

    /// <summary>Marks the challenge with <paramref name="nonce" /> used for <paramref name="lifetime" />.</summary>
    void MarkUsed(string nonce, TimeSpan lifetime);
}

/// <inheritdoc />
public sealed class CrossTenantChallengeReplayGuard(IMemoryCache cache) : ICrossTenantChallengeReplayGuard
{
    private static string Key(string nonce) => $"xt2fa-challenge-used:{nonce}";

    public bool IsUsed(string nonce) => cache.TryGetValue(Key(nonce), out _);

    public void MarkUsed(string nonce, TimeSpan lifetime)
        => cache.Set(Key(nonce), true, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = lifetime,
            Size = 1
        });
}
