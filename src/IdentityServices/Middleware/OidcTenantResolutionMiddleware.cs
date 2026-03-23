using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IdentityServerPersistence.SystemStores;
using Microsoft.AspNetCore.WebUtilities;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.Extensions.Options;

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
///   <item><c>/connect/authorize</c>: parses <c>acr_values=tenant:{tenantId}</c> from query string
///     and captures the authorization code from the 302 response for later tenant resolution</item>
///   <item><c>/connect/token</c>: reads the authorization code or refresh token from the form body
///     and resolves the tenant from the token-to-tenant mapping; also captures new refresh tokens
///     from the response for future exchanges</item>
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
    ILogger<OidcTenantResolutionMiddleware> logger,
    IOptions<OctoSystemConfiguration> octoSystemConfiguration)
{
    /// <summary>
    /// Maps authorization codes and refresh tokens to tenant IDs. Authorization codes are captured
    /// from <c>/connect/authorize</c> 302 responses; refresh tokens are captured from
    /// <c>/connect/token</c> JSON responses. Used by <c>/connect/token</c> to set the correct
    /// tenant context for user/client/resource lookups.
    /// </summary>
    private static readonly ConcurrentDictionary<string, (string TenantId, DateTime Expiry)> TokenToTenantMap = new();

    private static readonly TimeSpan AuthCodeEntryLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan RefreshTokenEntryLifetime = TimeSpan.FromDays(30);

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value;

        if (path != null && path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase))
        {
            await TryResolveTenantAsync(context, path);
        }

        var resolvedTenantId = context.Items[InfrastructureCommon.TenantIdName] as string;

        // For /connect/token with a resolved tenant, wrap the response body to capture
        // refresh tokens from the JSON response for future tenant resolution.
        var isTokenEndpoint = path != null &&
            path.StartsWith("/connect/token", StringComparison.OrdinalIgnoreCase);

        // For /connect/deviceauthorization with a resolved tenant, wrap the response body
        // to rewrite verification_uri and verification_uri_complete to the tenant-specific path.
        var isDeviceAuthEndpoint = path != null &&
            path.StartsWith("/connect/deviceauthorization", StringComparison.OrdinalIgnoreCase);

        var needsResponseCapture = resolvedTenantId != null && (isTokenEndpoint || isDeviceAuthEndpoint);

        if (needsResponseCapture)
        {
            var originalBody = context.Response.Body;
            using var memoryStream = new MemoryStream();
            context.Response.Body = memoryStream;

            await next(context);

            memoryStream.Position = 0;
            if (context.Response.StatusCode == StatusCodes.Status200OK)
            {
                if (isTokenEndpoint)
                {
                    CaptureRefreshTokenFromResponse(memoryStream, resolvedTenantId!);
                }
                else if (isDeviceAuthEndpoint)
                {
                    CaptureDeviceCodeFromResponse(memoryStream, resolvedTenantId!);
                    memoryStream.Position = 0;
                    var rewritten = RewriteDeviceVerificationUrls(memoryStream, resolvedTenantId!);
                    if (rewritten != null)
                    {
                        context.Response.ContentLength = rewritten.Length;
                        memoryStream.SetLength(0);
                        memoryStream.Write(rewritten);
                    }
                }

                memoryStream.Position = 0;
            }

            await memoryStream.CopyToAsync(originalBody);
            context.Response.Body = originalBody;
        }
        else
        {
            await next(context);
        }
    }

    private async Task TryResolveTenantAsync(HttpContext context, string path)
    {
        string? tenantId = null;

        if (path.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = ExtractTenantFromAcrValues(context);

            if (!string.IsNullOrEmpty(tenantId))
            {
                var capturedTenantId = tenantId;
                context.Response.OnStarting(() =>
                {
                    CaptureAuthorizationCode(context, capturedTenantId);
                    return Task.CompletedTask;
                });
            }
        }
        else if (path.StartsWith("/connect/deviceauthorization", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = await ExtractTenantFromFormAcrValuesAsync(context);
        }
        else if (path.StartsWith("/connect/token", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = await ResolveTenantFromTokenRequestAsync(context);
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

    /// <summary>
    /// Captures the authorization code from a 302 redirect response and maps it to the tenant ID.
    /// Called via <see cref="HttpResponse.OnStarting"/> after IdentityServer has set the Location header.
    /// </summary>
    private void CaptureAuthorizationCode(HttpContext context, string tenantId)
    {
        if (context.Response.StatusCode != StatusCodes.Status302Found)
        {
            return;
        }

        var location = context.Response.Headers.Location.ToString();
        var code = ExtractCodeFromRedirectUri(location);
        if (code == null)
        {
            return;
        }

        TokenToTenantMap[code] = (tenantId, DateTime.UtcNow.Add(AuthCodeEntryLifetime));
        logger.LogDebug("Captured authorization code → tenant '{TenantId}' mapping", tenantId);

        CleanupExpiredEntries();
    }

    /// <summary>
    /// Resolves the tenant for a <c>/connect/token</c> request by reading the authorization code
    /// or refresh token from the form body and looking up the captured tenant mapping.
    /// </summary>
    private async Task<string?> ResolveTenantFromTokenRequestAsync(HttpContext context)
    {
        context.Request.EnableBuffering();

        try
        {
            var form = await context.Request.ReadFormAsync();

            var grantType = form["grant_type"].FirstOrDefault();

            if (string.Equals(grantType, "authorization_code", StringComparison.Ordinal))
            {
                var code = form["code"].FirstOrDefault();
                if (code != null && TokenToTenantMap.TryRemove(code, out var entry))
                {
                    logger.LogDebug("Resolved tenant '{TenantId}' from authorization code for /connect/token",
                        entry.TenantId);
                    return entry.TenantId;
                }

                logger.LogWarning(
                    "No tenant mapping found for authorization code on /connect/token — user/client lookups will use system tenant");
            }
            else if (string.Equals(grantType, "urn:ietf:params:oauth:grant-type:device_code", StringComparison.Ordinal))
            {
                var deviceCode = form["device_code"].FirstOrDefault();
                if (deviceCode != null && TokenToTenantMap.TryGetValue($"device:{deviceCode}", out var entry))
                {
                    logger.LogDebug("Resolved tenant '{TenantId}' from device code for /connect/token",
                        entry.TenantId);
                    return entry.TenantId;
                }

                logger.LogWarning(
                    "No tenant mapping found for device code on /connect/token — user/client lookups will use system tenant");
            }
            else if (string.Equals(grantType, "refresh_token", StringComparison.Ordinal))
            {
                var refreshToken = form["refresh_token"].FirstOrDefault();
                if (refreshToken != null && TokenToTenantMap.TryGetValue(refreshToken, out var entry))
                {
                    logger.LogDebug("Resolved tenant '{TenantId}' from refresh token for /connect/token",
                        entry.TenantId);
                    return entry.TenantId;
                }

                // Fallback: look up the tenant from the persistent grant store (survives service restarts)
                if (refreshToken != null)
                {
                    var tenantId = await ResolveTenantFromPersistedGrantAsync(context, refreshToken);
                    if (tenantId != null)
                    {
                        // Re-populate the in-memory cache for subsequent requests
                        TokenToTenantMap[refreshToken] = (tenantId, DateTime.UtcNow.Add(RefreshTokenEntryLifetime));
                        logger.LogDebug(
                            "Resolved tenant '{TenantId}' from persistent grant store for /connect/token (recovered after restart)",
                            tenantId);
                        return tenantId;
                    }
                }

                logger.LogDebug(
                    "No tenant mapping found for refresh token on /connect/token — user/client lookups will use system tenant");
            }
        }
        finally
        {
            context.Request.Body.Position = 0;
        }

        return null;
    }

    /// <summary>
    /// Resolves the tenant ID from the persistent grant store by hashing the refresh token
    /// to obtain the grant key and reading the Description field. This is the fallback path
    /// used when the in-memory mapping is lost (e.g., after a service restart).
    /// </summary>
    private async Task<string?> ResolveTenantFromPersistedGrantAsync(HttpContext context, string refreshToken)
    {
        try
        {
            var grantStore = context.RequestServices.GetService<IOctoPersistentGrantStore>();
            if (grantStore == null)
            {
                return null;
            }

            // Duende IdentityServer stores grant keys as SHA256 hex hashes of the token handle
            var grantKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)));
            return await grantStore.GetTenantByGrantKeyAsync(grantKey);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to resolve tenant from persistent grant store");
            return null;
        }
    }

    /// <summary>
    /// Captures the <c>refresh_token</c> from a successful <c>/connect/token</c> JSON response
    /// and maps it to the tenant ID for future refresh token exchanges.
    /// </summary>
    private void CaptureRefreshTokenFromResponse(MemoryStream responseBody, string tenantId)
    {
        try
        {
            using var doc = JsonDocument.Parse(responseBody);
            if (doc.RootElement.TryGetProperty("refresh_token", out var refreshTokenElement))
            {
                var refreshToken = refreshTokenElement.GetString();
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    TokenToTenantMap[refreshToken] = (tenantId, DateTime.UtcNow.Add(RefreshTokenEntryLifetime));
                    logger.LogDebug("Captured refresh token → tenant '{TenantId}' mapping", tenantId);
                }
            }
        }
        catch
        {
            // Non-JSON response or parse error; skip
        }
    }

    /// <summary>
    /// Extracts the <c>code</c> query parameter from an OAuth2 redirect URI.
    /// </summary>
    internal static string? ExtractCodeFromRedirectUri(string? locationUri)
    {
        if (string.IsNullOrEmpty(locationUri))
        {
            return null;
        }

        try
        {
            var queryIndex = locationUri.IndexOf('?');
            if (queryIndex < 0)
            {
                return null;
            }

            var queryString = locationUri[(queryIndex + 1)..];
            var query = QueryHelpers.ParseQuery(queryString);

            if (query.TryGetValue("code", out var codeValues))
            {
                return codeValues.FirstOrDefault();
            }
        }
        catch
        {
            // Malformed URI; fall through
        }

        return null;
    }

    private static void CleanupExpiredEntries()
    {
        var now = DateTime.UtcNow;
        foreach (var kvp in TokenToTenantMap)
        {
            if (kvp.Value.Expiry < now)
            {
                TokenToTenantMap.TryRemove(kvp.Key, out _);
            }
        }
    }

    private static async Task<string?> ExtractTenantFromFormAcrValuesAsync(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            return null;
        }

        var form = await context.Request.ReadFormAsync();
        if (!form.TryGetValue("acr_values", out var acrValues))
        {
            return null;
        }

        return ParseTenantFromAcrValues(acrValues.ToString());
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

    /// <summary>
    /// Captures the device code from the device authorization JSON response and maps it to the tenant ID.
    /// The device code is later used to resolve the tenant during the token exchange.
    /// </summary>
    private void CaptureDeviceCodeFromResponse(MemoryStream responseBody, string tenantId)
    {
        try
        {
            using var doc = JsonDocument.Parse(responseBody);
            if (doc.RootElement.TryGetProperty("device_code", out var deviceCodeElement))
            {
                var deviceCode = deviceCodeElement.GetString();
                if (!string.IsNullOrEmpty(deviceCode))
                {
                    TokenToTenantMap[$"device:{deviceCode}"] =
                        (tenantId, DateTime.UtcNow.Add(AuthCodeEntryLifetime));
                    logger.LogDebug("Captured device code → tenant '{TenantId}' mapping", tenantId);
                    CleanupExpiredEntries();
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to capture device code from response");
        }
    }

    /// <summary>
    /// Rewrites <c>verification_uri</c> and <c>verification_uri_complete</c> in the device authorization
    /// JSON response to use the resolved tenant ID instead of the system tenant prefix.
    /// </summary>
    private byte[]? RewriteDeviceVerificationUrls(MemoryStream responseBody, string tenantId)
    {
        try
        {
            var json = Encoding.UTF8.GetString(responseBody.ToArray());
            var systemTenantId = octoSystemConfiguration.Value.SystemTenantId;
            var systemPath = $"/{systemTenantId}/device";
            var tenantPath = $"/{tenantId}/device";

            if (!json.Contains(systemPath, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var rewritten = json.Replace(systemPath, tenantPath, StringComparison.OrdinalIgnoreCase);
            logger.LogDebug(
                "Rewrote device verification URLs from '{SystemPath}' to '{TenantPath}'",
                systemPath, tenantPath);
            return Encoding.UTF8.GetBytes(rewritten);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to rewrite device verification URLs");
            return null;
        }
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
