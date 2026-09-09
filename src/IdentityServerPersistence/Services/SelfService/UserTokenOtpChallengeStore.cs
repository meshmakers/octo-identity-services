using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     <see cref="IOtpChallengeStore" /> backed by the ASP.NET Identity user-token store (AB#5123) —
///     the same durable per-user token store the 2FA authenticator key and recovery codes already
///     live in (see <c>ManageApiController</c>). The challenge is stored as one JSON token under a
///     dedicated login provider, keyed by destination, so it survives across identity-service
///     instances and is cleaned up on success, removal, or a fresh enrollment. No new CK type or
///     collection is introduced.
/// </summary>
public sealed class UserTokenOtpChallengeStore(UserManager<RtUser> userManager) : IOtpChallengeStore
{
    /// <summary>Login-provider bucket the OTP challenge tokens live under (internal, never an IdP).</summary>
    private const string OtpLoginProvider = "[SelfServicePhoneOtp]";

    public async Task StoreAsync(RtUser user, OtpChallenge challenge)
    {
        var payload = JsonSerializer.Serialize(challenge);
        await userManager.SetAuthenticationTokenAsync(user, OtpLoginProvider, TokenName(challenge.Destination),
            payload);
    }

    public async Task<OtpChallenge?> GetAsync(RtUser user, string destination)
    {
        var payload = await userManager.GetAuthenticationTokenAsync(user, OtpLoginProvider, TokenName(destination));
        if (string.IsNullOrEmpty(payload))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<OtpChallenge>(payload);
        }
        catch (JsonException)
        {
            // A malformed token is treated as no challenge — the user simply starts over.
            return null;
        }
    }

    public async Task RemoveAsync(RtUser user, string destination)
    {
        await userManager.RemoveAuthenticationTokenAsync(user, OtpLoginProvider, TokenName(destination));
    }

    /// <summary>One token per destination, so several pending numbers do not collide.</summary>
    private static string TokenName(string destination) => $"otp:{destination}";
}
