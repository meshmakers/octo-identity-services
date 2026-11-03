using System.Text.Json;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure;
using Meshmakers.Octo.Services.Infrastructure.Services;
using MongoDB.Driver;

namespace Meshmakers.Octo.Backend.IdentityServices.Middleware;

/// <summary>
///     AB#8177 — a token request that needs a tenant database which cannot be reached (MongoDB user missing or
///     rejected, database down) used to end in an unhandled exception: HTTP 500 without a reason, which octo-cli showed
///     as "the identity service could not be reached". The request now answers a clear OAuth error,
///     <c>503 temporarily_unavailable</c> with a description naming the tenant, and asks the
///     <see cref="TenantDatabaseUserHealer" /> to re-create a missing database user in the background.
/// </summary>
/// <remarks>
///     Applies to <c>/connect/token</c> only and only to database failures (MongoDB exceptions, timeouts); every other
///     exception still propagates to the global handler. Runs <b>before</b> <c>OidcTenantResolutionMiddleware</c> so that
///     its tenant lookup is covered too; the tenant it names in <c>HttpContext.Items</c> is read when the failure
///     happens (a failure inside the lookup itself answers without a tenant name).
/// </remarks>
internal sealed class TokenEndpointDatabaseFailureMiddleware(
    RequestDelegate next,
    ILogger<TokenEndpointDatabaseFailureMiddleware> logger)
{
    /// <summary>The OAuth error code of the response (RFC 6749 section 5.2 does not list it, RFC 6749 4.1.2.1 does).</summary>
    public const string ErrorCode = "temporarily_unavailable";

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments("/connect/token", StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        try
        {
            await next(context);
        }
        catch (Exception ex) when (IsDatabaseFailure(ex) && !context.RequestAborted.IsCancellationRequested &&
                                   !context.Response.HasStarted)
        {
            var tenantId = context.Items[InfrastructureCommon.TenantIdName] as string;
            var tenantText = tenantId is null ? "this token request" : $"the token request for tenant '{tenantId}'";
            var authFailure = TenantDatabaseUserHealer.IsAuthenticationFailure(ex);
            var cause = authFailure
                ? "MongoDB rejected the credentials of the tenant database user"
                : "the tenant database did not answer";
            logger.LogError(ex,
                "Token request (tenant '{TenantId}') failed: a tenant database is unavailable ({Cause}); answering " +
                "503 {Error} instead of an unhandled error", tenantId ?? "(not resolved)", cause, ErrorCode);

            // Same trigger policy as the probe guard: an authentication error or the timeout a SCRAM attempt against a
            // missing user runs into. Without a resolved tenant there is nobody to heal.
            if (tenantId is not null && (authFailure || HasTimeout(ex)) &&
                context.RequestServices.GetService<ISystemContext>() is { } systemContext)
            {
                var healLogger = logger;
                _ = Task.Run(() => TenantDatabaseUserHealer.Default.TryHealAsync(systemContext, tenantId, healLogger, ex));
            }

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers.RetryAfter = "60";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["error"] = ErrorCode,
                ["error_description"] =
                    $"The database of a tenant needed for {tenantText} is unavailable " +
                    $"({cause}). Retry in a minute; if it persists an administrator must check the MongoDB user of " +
                    "the tenant database."
            }));
        }
    }

    private static bool HasTimeout(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is TimeoutException)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsDatabaseFailure(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is MongoException or TimeoutException)
            {
                return true;
            }
        }

        return false;
    }
}

internal static class TokenEndpointDatabaseFailureMiddlewareExtensions
{
    public static IApplicationBuilder UseTokenEndpointDatabaseFailureHandling(this IApplicationBuilder app) =>
        app.UseMiddleware<TokenEndpointDatabaseFailureMiddleware>();
}
