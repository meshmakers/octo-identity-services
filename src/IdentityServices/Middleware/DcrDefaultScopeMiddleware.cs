using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services.DynamicClientRegistration;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Middleware;

/// <summary>
/// Defaults the <c>scope</c> parameter on <c>GET /connect/authorize</c> for dynamically-registered
/// clients (<c>octo-dcr-*</c>, RFC 7591 / AB#4338) when the client omits it.
/// </summary>
/// <remarks>
/// <para>
/// Some interactive MCP clients (observed with Claude Code) send the authorize request without a
/// <c>scope</c> parameter even though the protected-resource metadata advertises
/// <c>scopes_supported</c>. Duende IdentityServer hard-rejects a scopeless authorize request
/// ("scope is missing"), which surfaces as an opaque error page right after tenant selection.
/// </para>
/// <para>
/// RFC 6749 §3.3 explicitly allows the authorization server to fall back to a pre-defined default
/// when <c>scope</c> is omitted. For DCR clients the scope set is server-fixed at registration
/// (<see cref="DynamicClientRegistrationOptions.AllowedScopes"/> — client-supplied scopes are
/// ignored), so that same set is the only correct default and grants nothing the client could not
/// have requested. Non-DCR clients are never touched.
/// </para>
/// <para>
/// Must run <b>before</b> <c>UseIdentityServer()</c>. Only the query string is rewritten; PAR/form
/// posts are left alone (backend OIDC clients always send an explicit scope).
/// </para>
/// </remarks>
internal class DcrDefaultScopeMiddleware(
    RequestDelegate next,
    ILogger<DcrDefaultScopeMiddleware> logger,
    IOptions<OctoIdentityServicesOptions> identityOptions)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        if (HttpMethods.IsGet(request.Method) &&
            request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase) &&
            string.IsNullOrWhiteSpace(request.Query["scope"]))
        {
            var clientId = request.Query["client_id"].ToString();
            if (clientId.StartsWith(DynamicClientRegistrationService.ClientIdPrefix, StringComparison.Ordinal))
            {
                var defaultScope = string.Join(' ', identityOptions.Value.DynamicClientRegistration.AllowedScopes);
                var qb = new QueryBuilder();
                foreach (var (key, values) in request.Query)
                {
                    if (string.Equals(key, "scope", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    foreach (var value in values)
                    {
                        qb.Add(key, value ?? string.Empty);
                    }
                }

                qb.Add("scope", defaultScope);
                request.QueryString = qb.ToQueryString();

                logger.LogInformation(
                    "Defaulted missing scope to '{DefaultScope}' for DCR client '{ClientId}' on /connect/authorize",
                    defaultScope, clientId);
            }
        }

        await next(context);
    }
}

internal static class DcrDefaultScopeMiddlewareExtensions
{
    public static IApplicationBuilder UseDcrDefaultScope(this IApplicationBuilder app)
    {
        return app.UseMiddleware<DcrDefaultScopeMiddleware>();
    }
}
