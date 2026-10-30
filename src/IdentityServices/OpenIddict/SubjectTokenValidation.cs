using Meshmakers.Common.Shared;
using Microsoft.IdentityModel.Tokens;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Validation parameters for a <c>subject_token</c> that this service issued itself (AB#7860): token exchange
///     (<see cref="TenantExchangeProcessor" />) and on-behalf-of (<see cref="OnBehalfOfProcessor" />).
/// </summary>
/// <remarks>
///     <para>
///         Signature, issuer and lifetime are not enough: an id_token of a client with
///         <c>AlwaysIncludeUserClaimsInIdToken</c> (Studio, DCR clients) carries <c>sub</c>, <c>tenant_id</c> and
///         <c>amr</c> just like an access token, and id_tokens travel in places access tokens do not (e.g. as
///         <c>id_token_hint</c> in a logout URL). Only an access token is a valid subject: OpenIddict writes access
///         tokens with the JWT header <c>typ: at+jwt</c> (RFC 9068), id_tokens with <c>typ: JWT</c>.
///     </para>
///     <para>
///         For the RFC 8693 token exchange OpenIddict already refuses a non-access token before the processor runs
///         ("The specified token is not an access token."); the processor's own check is defence in depth. The
///         on-behalf-of grant is a custom flow that OpenIddict does not validate, so there this check is the only one.
///         The audience is deliberately not checked (platform convention <c>ValidateAudience = false</c>; a token
///         without an API scope has no audience).
///     </para>
/// </remarks>
public static class SubjectTokenValidation
{
    /// <summary>The JWT <c>typ</c> values of an access token (RFC 9068 § 2.1).</summary>
    public static readonly IReadOnlyList<string> AccessTokenTypes = ["at+jwt", "application/at+jwt"];

    /// <summary>Parameters that accept only an unexpired access token of <paramref name="authorityUrl" />.</summary>
    public static TokenValidationParameters ForAccessToken(string authorityUrl, IEnumerable<SecurityKey> signingKeys)
        => new()
        {
            ValidateIssuer = true,
            ValidIssuer = authorityUrl.EnsureEndsWith("/"),
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKeys = signingKeys,
            ValidTypes = AccessTokenTypes
        };
}
