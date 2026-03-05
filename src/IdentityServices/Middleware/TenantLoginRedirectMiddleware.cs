using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Meshmakers.Octo.Backend.IdentityServices.Middleware;

/// <summary>
/// Middleware that intercepts IdentityServer's 302 redirects to /{systemTenantId}/login (and other UI pages)
/// and rewrites the tenant prefix based on <c>acr_values=tenant:{tenantId}</c> in the ReturnUrl.
/// This enables OIDC clients to direct users to tenant-specific login pages by passing
/// <c>acr_values=tenant:{tenantId}</c> in the authorize request.
/// For logout redirects (which carry a <c>logoutId</c> instead of a <c>ReturnUrl</c>), the middleware
/// falls back to the tenant ID stored in <c>HttpContext.Items</c> by
/// <see cref="OidcTenantResolutionMiddleware"/> (resolved from the <c>id_token_hint</c> JWT).
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

        // IdentityServer may return absolute URLs (https://host/OctoSystem/login?...)
        // or relative paths (/OctoSystem/login?...). Extract the path portion for matching.
        string pathAndQuery;
        string locationPrefix;
        if (Uri.TryCreate(location, UriKind.Absolute, out var absoluteUri))
        {
            pathAndQuery = absoluteUri.PathAndQuery;
            locationPrefix = absoluteUri.GetLeftPart(UriPartial.Authority);
        }
        else
        {
            pathAndQuery = location;
            locationPrefix = string.Empty;
        }

        // Check if the redirect target starts with the system tenant prefix followed by a known UI path
        if (!pathAndQuery.StartsWith(_systemTenantPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Verify the path after the system tenant prefix is a known interaction path
        var pathAfterTenant = pathAndQuery.AsSpan(_systemTenantPrefix.Length);
        if (!pathAfterTenant.StartsWith("/login", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/consent", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/logout", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/error", StringComparison.OrdinalIgnoreCase) &&
            !pathAfterTenant.StartsWith("/device", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var tenantId = ExtractTenantFromLocation(pathAndQuery)
            ?? context.Items[InfrastructureCommon.TenantIdName] as string;
        if (string.IsNullOrEmpty(tenantId) ||
            string.Equals(tenantId, _systemTenantId, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // Rewrite /{systemTenantId}/... to /{tenantId}/..., preserving the scheme+host prefix if absolute
        var newLocation = locationPrefix + $"/{tenantId}" + pathAndQuery.Substring(_systemTenantPrefix.Length);
        context.Response.Headers.Location = newLocation;

        logger.LogDebug(
            "Rewrote login redirect from '{OriginalLocation}' to '{NewLocation}' for tenant '{TenantId}'",
            location, newLocation, tenantId);
    }

    private static string? ExtractTenantFromLocation(string pathAndQuery)
    {
        // The pathAndQuery looks like:
        // /OctoSystem/login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3F...%26acr_values%3Dtenant%3Achild1
        // We parse the ReturnUrl, then extract acr_values from it.
        var queryIndex = pathAndQuery.IndexOf('?');
        if (queryIndex < 0)
        {
            return null;
        }

        var queryString = pathAndQuery.Substring(queryIndex);
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
