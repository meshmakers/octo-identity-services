using Meshmakers.Octo.Services.Infrastructure;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Browser-visible OP session cookie backing OIDC Session Management. Keeps the
///     pre-migration cookie name <c>idsrv.session</c> so existing consumers and tools keep
///     working. It carries the server-side session id, is deliberately
///     NOT HttpOnly (the <c>/connect/checksession</c> iframe reads it via <c>document.cookie</c>)
///     and is tenant-suffixed like the auth cookie (see <c>TenantCookieManager</c>) so concurrent
///     tenant sessions in one browser signal independently.
/// </summary>
/// <remarks>
///     The cookie value is only the opaque session id — it grants nothing by itself; the actual
///     session lives in the HttpOnly auth cookie plus the server-side session record.
/// </remarks>
public static class SessionCheckCookie
{
    public const string BaseName = "idsrv.session";

    public static string ResolveName(HttpContext context)
    {
        var tenantId = context.Items[InfrastructureCommon.TenantIdName] as string;
        return string.IsNullOrEmpty(tenantId) ? BaseName : $"{BaseName}.{tenantId.ToLowerInvariant()}";
    }

    public static void Issue(HttpContext context, string sessionId, DateTimeOffset? expires)
    {
        context.Response.Cookies.Append(ResolveName(context), sessionId, new CookieOptions
        {
            HttpOnly = false,
            // Secure follows the request scheme: all real deployments are HTTPS; the plain-HTTP
            // integration-test host would otherwise never replay a Secure cookie.
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.None,
            IsEssential = true,
            Path = "/",
            Expires = expires
        });
    }

    public static void Delete(HttpContext context)
    {
        context.Response.Cookies.Delete(ResolveName(context), new CookieOptions
        {
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.None,
            Path = "/"
        });
    }

    public static string? Read(HttpContext context)
        => context.Request.Cookies.TryGetValue(ResolveName(context), out var value) ? value : null;
}
