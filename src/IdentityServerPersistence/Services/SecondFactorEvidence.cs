using System.Security.Claims;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Second-factor evidence across tenant boundaries (AB#7804): the <c>amr</c> (authentication methods
///     references, RFC 8176) value <c>mfa</c>.
/// </summary>
/// <remarks>
///     <para>
///         ASP.NET Core Identity stamps <c>amr=mfa</c> on the session when a sign-in completed a second factor
///         (<c>SignInManager.TwoFactor*SignInAsync</c>) and <c>amr=pwd</c> for a password-only sign-in.
///         <c>AuthorizeController</c> copies the session's <c>amr</c> into the access token, so the same evidence
///         is visible to every cross-tenant entry point: the cookie session of the source tenant
///         (<c>cross-tenant-token</c>, <c>tenant-switch</c>, cross-tenant device approval), the access token
///         (token exchange), and the sessions and tokens this service issues in the target tenant, which carry
///         the evidence on so that a further hop (grandchild tenant, chained exchange) can rely on it.
///     </para>
///     <para>
///         A session that a "remember this machine" cookie skipped the second factor for carries only
///         <c>amr=pwd</c>; such a user signs in once more with the second factor before crossing a tenant
///         boundary. Fail closed is deliberate.
///     </para>
/// </remarks>
public static class SecondFactorEvidence
{
    /// <summary>The claim type ASP.NET Core Identity and OpenID Connect use for authentication methods.</summary>
    public const string AuthenticationMethodClaimType = "amr";

    /// <summary>The <c>amr</c> value of a sign-in that completed a second factor.</summary>
    public const string MultiFactorMethod = "mfa";

    /// <summary>
    ///     Stable, machine-readable prefix of the denials returned when the source user has 2FA and the presented
    ///     proof carries no second-factor evidence. Clients match on this prefix, never on the free text after it.
    /// </summary>
    public const string RequiredMarker = "second_factor_required";

    /// <summary>Whether the claims carry <c>amr=mfa</c>.</summary>
    public static bool IsPresent(IEnumerable<Claim>? claims)
        => claims?.Any(c => c.Type == AuthenticationMethodClaimType &&
                            string.Equals(c.Value, MultiFactorMethod, StringComparison.Ordinal)) == true;

    /// <summary>A new <c>amr=mfa</c> claim for a session or token issued on verified evidence.</summary>
    public static Claim CreateClaim() => new(AuthenticationMethodClaimType, MultiFactorMethod);
}
