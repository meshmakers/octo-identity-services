namespace Meshmakers.Octo.Backend.Authentication;

/// <summary>
///     Central authentication scheme and cookie names used across the identity service.
///     These names are load-bearing: <c>TenantCookieManager</c> appends a <c>.{tenantId}</c>
///     suffix to the corresponding cookie names to scope sessions per tenant, and the dynamic
///     external providers (Google, Microsoft, Facebook, Azure Entra ID) sign in against
///     <see cref="ExternalCookieScheme" />.
/// </summary>
/// <remarks>
///     AB#4989 (OpenIddict migration): the values currently match the scheme names Duende
///     IdentityServer registers, so introducing these constants changes no behavior. With the
///     swap to OpenIddict the Duende-owned schemes (<see cref="ServerSsoCookieScheme" />,
///     <see cref="ServerSsoSessionCookieScheme" />) disappear and
///     <see cref="ExternalCookieScheme" /> switches to ASP.NET Identity's own external scheme.
///     Cookie NAMES may change at that cutover (all sessions end anyway — see
///     docs/CONCEPT-OPENIDDICT-MIGRATION.md §2) but must stay stable from then on.
/// </remarks>
public static class OctoAuthSchemes
{
    /// <summary>
    ///     The ASP.NET Identity application cookie scheme carrying the user session
    ///     (cookie name <c>.AspNetCore.Identity.Application</c>, tenant-scoped).
    /// </summary>
    public const string ApplicationCookieScheme = "Identity.Application";

    /// <summary>
    ///     The cookie scheme external providers sign in against before the callback
    ///     converts the external identity into an application session.
    ///     Currently Duende's <c>idsrv.external</c>; becomes <c>Identity.External</c>
    ///     with the OpenIddict swap.
    /// </summary>
    public const string ExternalCookieScheme = "idsrv.external";

    /// <summary>
    ///     Duende's own SSO session cookie scheme (<c>idsrv</c>). Signed out explicitly on
    ///     logout so the SSO session does not survive <c>SignOutAsync</c> on the application
    ///     cookie. Removed with the OpenIddict swap (OpenIddict has no separate SSO cookie).
    /// </summary>
    public const string ServerSsoCookieScheme = "idsrv";

    /// <summary>
    ///     Duende's session-management cookie scheme (<c>idsrv.session</c>, check-session
    ///     iframe support). Removed with the OpenIddict swap.
    /// </summary>
    public const string ServerSsoSessionCookieScheme = "idsrv.session";
}
