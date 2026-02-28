using System.Text;
using System.Text.Json;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;

namespace Meshmakers.Octo.Backend.IdentityServices.Middleware;

/// <summary>
/// Middleware that resolves the tenant for OIDC <c>/connect/*</c> endpoints which don't include
/// a <c>{tenantId}</c> route segment. Without this middleware, TenantMiddleware defaults to the
/// system tenant, causing <see cref="Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions"/>
/// to use the wrong tenant-scoped cookie.
/// </summary>
/// <remarks>
/// <para>
/// <b>Resolution strategy by endpoint:</b>
/// <list type="bullet">
///   <item><c>/connect/authorize</c>: parses <c>acr_values=tenant:{tenantId}</c> from query string</item>
///   <item><c>/connect/endsession</c>: decodes <c>id_token_hint</c> JWT payload to read <c>tenant_id</c>
///     claim; falls back to <c>acr_values</c></item>
/// </list>
/// </para>
/// <para>
/// This middleware must run <b>after</b> routing (so route values are available) and <b>before</b>
/// <c>UseIdentityServer()</c> (which triggers authentication).
/// </para>
/// </remarks>
internal class OidcTenantResolutionMiddleware(
    RequestDelegate next,
    ILogger<OidcTenantResolutionMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value;

        if (path != null && path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase))
        {
            await TryResolveTenantAsync(context, path);
        }

        await next(context);
    }

    private async Task TryResolveTenantAsync(HttpContext context, string path)
    {
        string? tenantId = null;

        if (path.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = ExtractTenantFromAcrValues(context);
        }
        else if (path.StartsWith("/connect/endsession", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = ExtractTenantFromIdTokenHint(context) ?? ExtractTenantFromAcrValues(context);
        }

        if (string.IsNullOrEmpty(tenantId))
        {
            return;
        }

        var systemContext = context.RequestServices.GetRequiredService<ISystemContext>();
        var tenantRepository = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        if (tenantRepository == null)
        {
            logger.LogWarning("OIDC tenant resolution: tenant '{TenantId}' not found", tenantId);
            return;
        }

        context.Items[InfrastructureCommon.TenantRepositoryName] = tenantRepository;
        context.Items[InfrastructureCommon.TenantIdName] = tenantRepository.TenantId;

        logger.LogDebug("OIDC tenant resolved to '{TenantId}' for {Path}", tenantRepository.TenantId, path);
    }

    private static string? ExtractTenantFromAcrValues(HttpContext context)
    {
        if (!context.Request.Query.TryGetValue("acr_values", out var acrValues))
        {
            return null;
        }

        return ParseTenantFromAcrValues(acrValues.ToString());
    }

    internal static string? ParseTenantFromAcrValues(string acrValues)
    {
        var values = acrValues.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var value in values)
        {
            if (value.StartsWith("tenant:", StringComparison.OrdinalIgnoreCase))
            {
                var tenantId = value.Substring("tenant:".Length);
                if (!string.IsNullOrEmpty(tenantId))
                {
                    return tenantId;
                }
            }
        }

        return null;
    }

    private string? ExtractTenantFromIdTokenHint(HttpContext context)
    {
        if (!context.Request.Query.TryGetValue("id_token_hint", out var idTokenHint))
        {
            return null;
        }

        return ExtractTenantFromJwtPayload(idTokenHint.ToString());
    }

    /// <summary>
    /// Extracts the <c>tenant_id</c> claim from the JWT payload without signature verification.
    /// The token has already been validated by IdentityServer when it was issued; we only need
    /// the tenant routing hint.
    /// </summary>
    internal static string? ExtractTenantFromJwtPayload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }

        try
        {
            var payload = parts[1];

            // Add padding if necessary for base64url decoding
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }

            // base64url → base64
            payload = payload.Replace('-', '+').Replace('_', '/');

            var bytes = Convert.FromBase64String(payload);
            using var doc = JsonDocument.Parse(bytes);

            if (doc.RootElement.TryGetProperty("tenant_id", out var tenantIdElement))
            {
                return tenantIdElement.GetString();
            }
        }
        catch (Exception)
        {
            // Malformed JWT; fall through to null
        }

        return null;
    }
}

/// <summary>
/// Extension method to register the <see cref="OidcTenantResolutionMiddleware"/>.
/// </summary>
internal static class OidcTenantResolutionMiddlewareExtensions
{
    public static IApplicationBuilder UseOidcTenantResolution(this IApplicationBuilder app)
    {
        return app.UseMiddleware<OidcTenantResolutionMiddleware>();
    }
}
