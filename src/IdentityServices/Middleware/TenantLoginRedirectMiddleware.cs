using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Meshmakers.Octo.Backend.IdentityServices.Middleware;

/// <summary>
/// Middleware that intercepts IdentityServer's 302 redirects to /{systemTenantId}/login (and other UI pages)
/// and rewrites the tenant prefix based on <c>acr_values=tenant:{tenantId}</c> in the ReturnUrl.
/// This enables OIDC clients to direct users to tenant-specific login pages by passing
/// <c>acr_values=tenant:{tenantId}</c> in the authorize request.
/// </summary>
internal class TenantLoginRedirectMiddleware(
    RequestDelegate next,
    ILogger<TenantLoginRedirectMiddleware> logger,
    IOptions<OctoSystemConfiguration> octoSystemConfiguration)
{
    private readonly string _systemTenantId = octoSystemConfiguration.Value.SystemTenantId;
    private readonly string _systemTenantPrefix = $"/{octoSystemConfiguration.Value.SystemTenantId}";

    public async Task InvokeAsync(HttpContext context)
    {
        await next(context);

        if (context.Response.StatusCode != 302)
        {
            return;
        }

        var location = context.Response.Headers.Location.ToString();
        if (string.IsNullOrEmpty(location))
        {
            return;
        }

        // Check if the redirect target starts with the system tenant prefix followed by a known UI path
        if (!location.StartsWith(_systemTenantPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Verify the path after the system tenant prefix is a known interaction path
        var pathAfterTenant = location.AsSpan(_systemTenantPrefix.Length);
        if (!pathAfterTenant.StartsWith("/login", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/consent", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/logout", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/error", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/device", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var tenantId = ExtractTenantFromLocation(location);
        if (string.IsNullOrEmpty(tenantId) ||
            string.Equals(tenantId, _systemTenantId, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Rewrite /{systemTenantId}/... to /{tenantId}/...
        var newLocation = $"/{tenantId}" + location.Substring(_systemTenantPrefix.Length);
        context.Response.Headers.Location = newLocation;

        logger.LogDebug(
            "Rewrote login redirect from '{OriginalLocation}' to '{NewLocation}' for tenant '{TenantId}'",
            location, newLocation, tenantId);
    }

    private static string? ExtractTenantFromLocation(string location)
    {
        // The location looks like:
        // /System/login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3F...%26acr_values%3Dtenant%3Achild1
        // We parse the ReturnUrl, then extract acr_values from it.
        var queryIndex = location.IndexOf('?');
        if (queryIndex < 0)
        {
            return null;
        }

        var queryString = location.Substring(queryIndex);
        var queryParams = QueryHelpers.ParseQuery(queryString);

        if (!queryParams.TryGetValue("ReturnUrl", out var returnUrl) ||
            StringValues.IsNullOrEmpty(returnUrl))
        {
            return null;
        }

        // The ReturnUrl is the IdentityServer authorize callback URL with original parameters
        var returnUrlString = returnUrl.ToString();
        var returnUrlQueryIndex = returnUrlString.IndexOf('?');
        if (returnUrlQueryIndex < 0)
        {
            return null;
        }

        var returnUrlQuery = returnUrlString.Substring(returnUrlQueryIndex);
        var returnUrlParams = QueryHelpers.ParseQuery(returnUrlQuery);

        // Look for acr_values containing tenant:{tenantId}
        if (!returnUrlParams.TryGetValue("acr_values", out var acrValues) ||
            StringValues.IsNullOrEmpty(acrValues))
        {
            return null;
        }

        return ExtractTenantFromAcrValues(acrValues.ToString());
    }

    private static string? ExtractTenantFromAcrValues(string acrValues)
    {
        // acr_values is a space-separated list of values per OIDC spec
        // We look for "tenant:{tenantId}"
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
}

/// <summary>
/// Extension method to register the <see cref="TenantLoginRedirectMiddleware"/>.
/// </summary>
internal static class TenantLoginRedirectMiddlewareExtensions
{
    public static IApplicationBuilder UseTenantLoginRedirect(this IApplicationBuilder app)
    {
        return app.UseMiddleware<TenantLoginRedirectMiddleware>();
    }
}
