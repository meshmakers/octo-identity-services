using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Meshmakers.Octo.Backend.IdentityServices.Cookies;

/// <summary>
/// Custom <see cref="ICookieManager"/> that appends <c>.{tenantId}</c> to scoped cookie names
/// based on <c>HttpContext.Items["tenantId"]</c>. This ensures that authentication cookies are
/// isolated per tenant, preventing cross-tenant session leakage.
/// </summary>
/// <remarks>
/// <para>
/// <b>Scoped cookies</b> (tenant suffix added):
/// <list type="bullet">
///   <item><c>Identity.Application</c> — main auth cookie</item>
///   <item><c>idsrv</c> — IdentityServer session cookie</item>
/// </list>
/// </para>
/// <para>
/// <b>Global cookies</b> (unchanged):
/// <list type="bullet">
///   <item><c>Identity.External</c> — written at <c>/signin-google</c> (no tenant in URL)</item>
///   <item><c>Identity.TwoFactorUserId</c>, <c>Identity.TwoFactorRememberMe</c> — short-lived, single login flow</item>
/// </list>
/// </para>
/// </remarks>
internal class TenantCookieManager : ICookieManager
{
    private static readonly HashSet<string> ScopedCookieNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".AspNetCore.Identity.Application",
        "idsrv",
        "idsrv.session"
    };

    private readonly ChunkingCookieManager _inner = new();

    public string? GetRequestCookie(HttpContext context, string key)
    {
        var scopedKey = ResolveScopedKey(context, key);
        return _inner.GetRequestCookie(context, scopedKey);
    }

    public void AppendResponseCookie(HttpContext context, string key, string? value,
        CookieOptions options)
    {
        var scopedKey = ResolveScopedKey(context, key);
        _inner.AppendResponseCookie(context, scopedKey, value, options);
    }

    public void DeleteCookie(HttpContext context, string key, CookieOptions options)
    {
        var scopedKey = ResolveScopedKey(context, key);
        _inner.DeleteCookie(context, scopedKey, options);
    }

    internal static string ResolveScopedKey(HttpContext context, string key)
    {
        if (!ScopedCookieNames.Contains(key))
        {
            return key;
        }

        var tenantId = context.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(tenantId))
        {
            return key;
        }

        return $"{key}.{tenantId.ToLowerInvariant()}";
    }
}
