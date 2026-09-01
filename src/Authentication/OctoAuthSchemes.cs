namespace Meshmakers.Octo.Backend.Authentication;

/// <summary>
///     Central authentication scheme and cookie names used across the identity service.
///     These names are load-bearing: <c>TenantCookieManager</c> appends a <c>.{tenantId}</c>
///     suffix to the corresponding cookie names to scope sessions per tenant, and the dynamic
///     external providers (Google, Microsoft, Facebook, Azure Entra ID) sign in against
///     <see cref="ExternalCookieScheme" />.
/// </summary>
/// <remarks>
///     AB#4989/AB#4996: since the swap to OpenIddict the values are ASP.NET Identity's own
///     scheme names — the Duende-owned schemes (<c>idsrv</c>, <c>idsrv.session</c>,
///     <c>idsrv.external</c>) no longer exist. Cookie names changed at the cutover (all
///     sessions ended by design, see docs/CONCEPT-OPENIDDICT-MIGRATION.md §2) and must stay
///     stable from here on.
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
    ///     converts the external identity into an application session
    ///     (ASP.NET Identity's external scheme).
    /// </summary>
    public const string ExternalCookieScheme = "Identity.External";
}
