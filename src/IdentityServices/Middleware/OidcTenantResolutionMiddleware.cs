using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

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
///   <item><c>/connect/authorize</c>: parses <c>acr_values=tenant:{tenantId}</c> from the query string, or the
///     tenant marked into a PAR <c>request_uri</c>, and marks the issued authorization code with the tenant</item>
///   <item><c>/connect/par</c>: reads <c>acr_values</c> from the form and marks the issued <c>request_uri</c> with the
///     tenant (or the discovery scope, AB#5311)</item>
///   <item><c>/connect/token</c>: reads the tenant from the marker of the authorization code, refresh token or device
///     code (AB#7891/AB#7892), or from <c>acr_values</c>; marks the issued refresh token with the tenant</item>
///   <item><c>/connect/revocation</c>, <c>/connect/introspect</c>: tenant marker of the <c>token</c> field, else the
///     bearer token's <c>tenant_id</c></item>
///   <item><c>/connect/deviceauthorization</c>: reads <c>acr_values=tenant:{tenantId}</c> from the form,
///     marks the issued <c>device_code</c> with the tenant and points the verification URIs to the
///     tenant's device page (AB#7891)</item>
///   <item><c>/connect/deviceverification</c>: reads the tenant hint <c>acr_values=tenant:{tenantId}</c>
///     the device page sends (AB#7891)</item>
///   <item><c>/connect/endsession</c>: decodes <c>id_token_hint</c> JWT payload to read <c>tenant_id</c>
///     claim; falls back to <c>acr_values</c></item>
/// </list>
/// </para>
/// <para>
/// <b>No process-local state (AB#7892).</b> Every value a later request sends back carries its tenant
/// (<see cref="OidcTenantMarker" />), so identity can run with several replicas and restart without breaking
/// in-flight sign-ins or refreshes.
/// </para>
/// <para>
/// This middleware must run <b>after</b> routing (so route values are available) and <b>before</b>
/// <c>UseAuthentication()</c> and the OpenIddict server middleware (which trigger authentication).
/// </para>
/// </remarks>
internal class OidcTenantResolutionMiddleware(
    RequestDelegate next,
    ILogger<OidcTenantResolutionMiddleware> logger,
    IOptions<OctoSystemConfiguration> octoSystemConfiguration)
{
    // AB#7892 — no process-local state. The tenant of every value that a later request sends back travels inside the
    // value itself (OidcTenantMarker), so any replica and a restarted process resolve it. Decision per entry type:
    //  * Authorization code (persisted per tenant as RtOAuthToken): marked on the /connect/authorize
    //    response (Location query/fragment or form_post field), stripped on /connect/token. Lives exactly as long as
    //    the code; nothing extra stored.
    //  * PAR request_uri (+ the AB#5311 discovery scope): marked inside the URN on the /connect/par response,
    //    stripped on /connect/authorize?request_uri=… . Lives exactly as long as the request token.
    //  * Refresh token (persisted per tenant): marked on every /connect/token response that carries one, stripped on
    //    grant refresh_token and on /connect/revocation + /connect/introspect. Rotated tokens are marked again.
    //  * Device code: marked since AB#7891.
    // A store lookup ("which tenant holds this token?") was rejected: codes and refresh tokens are encrypted
    // self-contained tokens whose store id is only readable after decryption, so the tenant would have to be found by
    // scanning every tenant database. A shared collection with a TTL index was not needed: every key can be carried.
    // A changed marker only points OpenIddict at a token store that does not hold the value — rejected like any
    // unknown value (fail closed). Values without a marker (issued before AB#7892) keep today's behaviour: acr_values
    // where the grant honours it, otherwise the system tenant — where a token of another tenant is unknown as well.

    /// <summary>
    /// Matches the authorization code from an HTML form_post response body.
    /// OpenIddict returns <c>&lt;input type='hidden' name='code' value='...' /&gt;</c>.
    /// </summary>
    private static readonly Regex FormPostCodePattern = new(
        @"name=[""']code[""']\s+value=[""']([^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value;

        if (path != null && path.StartsWith("/connect/", StringComparison.OrdinalIgnoreCase))
        {
            var handled = await TryResolveTenantAsync(context, path);
            if (handled)
            {
                return; // Response already written (redirect to tenant discovery)
            }
        }

        var resolvedTenantId = context.Items[InfrastructureCommon.TenantIdName] as string;

        // For /connect/token with a resolved tenant, wrap the response body to mark the issued
        // refresh token with the tenant (AB#7892, OidcTenantMarker).
        var isTokenEndpoint = path != null &&
            path.StartsWith("/connect/token", StringComparison.OrdinalIgnoreCase);

        // For /connect/deviceauthorization with a resolved tenant, wrap the response body
        // to rewrite verification_uri and verification_uri_complete to the tenant-specific path
        // and to mark the device_code with the tenant (AB#7891, OidcTenantMarker).
        var isDeviceAuthEndpoint = path != null &&
            path.StartsWith("/connect/deviceauthorization", StringComparison.OrdinalIgnoreCase);

        // For /connect/authorize with a resolved tenant, wrap the response body to mark
        // the authorization code with the tenant (AB#7892) in both redirects (response_mode=query/fragment)
        // and 200 HTML responses (response_mode=form_post).
        var isAuthorizeEndpoint = path != null &&
            path.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase);

        // For /connect/par with a resolved tenant, wrap the response body to mark
        // the issued request_uri (RFC 9126) with the tenant (AB#7892). The follow-up
        // /connect/authorize?request_uri=... reads the tenant back from it (acr_values is not on the URL anymore).
        var isParEndpoint = path != null &&
            path.StartsWith("/connect/par", StringComparison.OrdinalIgnoreCase);

        // A scope-only PAR resolves no tenant but still needs its request_uri marked with the scope (AB#5311).
        var parScope = isParEndpoint ? context.Items[ParDiscoveryScopeItem] as string : null;
        var needsResponseCapture = (resolvedTenantId != null &&
                                    (isTokenEndpoint || isDeviceAuthEndpoint || isAuthorizeEndpoint || isParEndpoint))
                                   || parScope != null;

        if (needsResponseCapture)
        {
            var originalBody = context.Response.Body;
            using var memoryStream = new MemoryStream();
            context.Response.Body = memoryStream;

            try
            {
                await next(context);

                memoryStream.Position = 0;
                byte[]? rewritten = null;
                if (isAuthorizeEndpoint)
                {
                    rewritten = MarkAuthorizationCode(context, memoryStream, resolvedTenantId!);
                }
                else if (isParEndpoint &&
                         (context.Response.StatusCode == StatusCodes.Status201Created ||
                          context.Response.StatusCode == StatusCodes.Status200OK))
                {
                    rewritten = MarkRequestUriInParResponse(memoryStream, resolvedTenantId, parScope);
                }
                else if (context.Response.StatusCode == StatusCodes.Status200OK)
                {
                    if (isTokenEndpoint)
                    {
                        rewritten = MarkRefreshTokenInTokenResponse(memoryStream, resolvedTenantId!);
                    }
                    else if (isDeviceAuthEndpoint)
                    {
                        rewritten = RewriteDeviceAuthorizationResponse(memoryStream, resolvedTenantId!);
                    }
                }

                if (rewritten != null)
                {
                    context.Response.ContentLength = rewritten.Length;
                    memoryStream.SetLength(0);
                    memoryStream.Write(rewritten);
                }

                memoryStream.Position = 0;
                await memoryStream.CopyToAsync(originalBody);
            }
            finally
            {
                // AB#8177: always hand the original body back. When the inner pipeline throws, the buffer is
                // disposed here; an outer middleware (TokenEndpointDatabaseFailureMiddleware) must still be able
                // to write its error response. The buffered content is dropped on failure (never copied).
                context.Response.Body = originalBody;
            }
        }
        else
        {
            await next(context);
        }
    }

    /// <summary>
    /// Tries to resolve the tenant from the request. Returns <c>true</c> if the response was
    /// already written (e.g., redirect to tenant discovery), meaning the caller should not call <c>next()</c>.
    /// </summary>
    private async Task<bool> TryResolveTenantAsync(HttpContext context, string path)
    {
        string? tenantId = null;

        if (path.StartsWith("/connect/authorize", StringComparison.OrdinalIgnoreCase))
        {
            // The URL as the client sent it — the discovery redirects below hand it back unchanged,
            // including a marked request_uri.
            var authorizeUrl = context.Request.GetEncodedUrl();

            // PAR (RFC 9126): when the client used /connect/par, the follow-up authorize call
            // carries only request_uri=urn:ietf:params:oauth:request_uri:... — the tenant (or the
            // AB#5311 discovery scope) was marked into it on /connect/par (AB#7892). The marker is
            // removed here, so OpenIddict sees the request_uri it issued.
            var (requestUriTenantId, requestUriScopeTenantId) = UnmarkRequestUri(context);
            tenantId = requestUriTenantId;

            if (string.IsNullOrEmpty(tenantId))
            {
                tenantId = ExtractTenantFromAcrValues(context);
            }

            if (!string.IsNullOrEmpty(tenantId))
            {
                // Authorization code capture is handled in InvokeAsync via response body interception,
                // which supports both 302 redirects (response_mode=query) and 200 HTML responses (response_mode=form_post).
            }
            else
            {
                // No acr_values=tenant:X — check for existing session cookies before
                // redirecting to tenant discovery page
                var sessionTenants = FindTenantIdsFromSessionCookies(context);

                // AB#5311: an app host that serves one tenant subtree names it as a second
                // acr_values entry, `tenant_scope:{rootTenantId}`. The scope narrows both
                // shortcuts below — a session cookie for a tenant outside the subtree must not
                // short-circuit the discovery — and the discovery page's lookup.
                var scopeTenantId = ExtractScopeFromAcrValues(context) ?? requestUriScopeTenantId;
                if (!string.IsNullOrEmpty(scopeTenantId) && sessionTenants.Count == 1)
                {
                    var discovery = context.RequestServices.GetRequiredService<ITenantDiscoveryService>();
                    var scope = await discovery.GetScopeDescendantsAsync(scopeTenantId);
                    if (scope == null || !scope.Contains(sessionTenants[0]))
                    {
                        logger.LogDebug(
                            "Single session cookie for tenant '{TenantId}' is outside the discovery scope '{ScopeTenantId}' — not shortcutting",
                            sessionTenants[0], scopeTenantId);
                        sessionTenants.Clear();
                    }
                }

                if (sessionTenants.Count == 1)
                {
                    // Single active session — redirect directly with acr_values, skip discovery
                    var singleTenant = sessionTenants[0];
                    var url = new Uri(authorizeUrl, UriKind.Absolute);
                    var query = QueryHelpers.ParseQuery(url.Query);
                    query["acr_values"] = $"tenant:{singleTenant}";
                    var newUrl = QueryHelpers.AddQueryString(
                        url.GetLeftPart(UriPartial.Path),
                        query.ToDictionary(k => k.Key, v => (string?)v.Value.ToString()));
                    context.Response.Redirect(newUrl);
                    logger.LogDebug(
                        "Single session cookie found for tenant '{TenantId}' — redirecting with acr_values",
                        singleTenant);
                    return true;
                }

                if (sessionTenants.Count > 1)
                {
                    // Multiple active sessions — redirect to tenant discovery without
                    // pre-resolved tenants. Session cookies are per-browser (not per-user),
                    // so passing them as knownTenants could show tenants the current user
                    // doesn't belong to. The discovery page requires email/username input
                    // to verify actual tenant membership.
                    var discoveryUrl = BuildDiscoveryUrl(authorizeUrl, scopeTenantId);
                    context.Response.Redirect(discoveryUrl);
                    logger.LogDebug(
                        "Multiple session cookies found ({Count} tenants) — redirecting to tenant discovery",
                        sessionTenants.Count);
                    return true;
                }

                // No active sessions — redirect to tenant discovery page (email input)
                var fallbackDiscoveryUrl = BuildDiscoveryUrl(authorizeUrl, scopeTenantId);
                context.Response.Redirect(fallbackDiscoveryUrl);
                logger.LogDebug("No acr_values on /connect/authorize — redirecting to tenant discovery (scope '{ScopeTenantId}')",
                    scopeTenantId ?? "-");
                return true;
            }
        }
        else if (path.StartsWith("/connect/par", StringComparison.OrdinalIgnoreCase))
        {
            // RFC 9126 Pushed Authorization Request: the client POSTs the full set of
            // authorization parameters (including acr_values=tenant:X) to /connect/par and
            // receives a request_uri to use on the subsequent /connect/authorize call.
            tenantId = await ExtractTenantFromFormAcrValuesAsync(context);

            // AB#5311: a scope-only PAR (the discovery case) names no tenant, so nothing
            // would be captured and the follow-up authorize call would run an unscoped
            // discovery. Remember the scope for the response capture below; it is stored
            // next to the request_uri and restored on /connect/authorize?request_uri=...
            if (string.IsNullOrEmpty(tenantId))
            {
                var parScope = await ExtractScopeFromFormAcrValuesAsync(context);
                if (!string.IsNullOrEmpty(parScope))
                {
                    context.Items[ParDiscoveryScopeItem] = parScope;
                }
            }
        }
        else if (path.StartsWith("/connect/deviceauthorization", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = await ExtractTenantFromFormAcrValuesAsync(context);
        }
        else if (path.StartsWith("/connect/deviceverification", StringComparison.OrdinalIgnoreCase))
        {
            // AB#4993/AB#7891: the device verification endpoint has no tenant route segment. The
            // Angular device page runs under /{tenantId}/device and names that tenant as
            // acr_values=tenant:{tenantId} (query on GET, form on POST). OpenIddict then validates
            // the user_code against that tenant's token store only — a code of another tenant is an
            // unknown code there. No server-side state, so any replica can serve the request.
            tenantId = await ResolveTenantForDeviceVerificationAsync(context);
        }
        else if (path.StartsWith("/connect/token", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = await ResolveTenantFromTokenRequestAsync(context);
        }
        else if (path.StartsWith("/connect/endsession", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = ExtractTenantFromIdTokenHint(context) ?? ExtractTenantFromAcrValues(context);
        }
        else if (path.StartsWith("/connect/introspect", StringComparison.OrdinalIgnoreCase)
                 || path.StartsWith("/connect/revocation", StringComparison.OrdinalIgnoreCase))
        {
            // AB#7892: a refresh token sent for revocation/introspection carries its tenant marker;
            // it names the token store the token lives in. Otherwise the caller's bearer token.
            tenantId = await UnmarkFormTokenAsync(context) ?? ExtractTenantFromBearerToken(context);
        }
        else if (path.StartsWith("/connect/userinfo", StringComparison.OrdinalIgnoreCase))
        {
            tenantId = ExtractTenantFromBearerToken(context);
        }

        if (string.IsNullOrEmpty(tenantId))
        {
            return false;
        }

        var sysCtx = context.RequestServices.GetRequiredService<ISystemContext>();
        var tenantRepository = await sysCtx.TryFindTenantRepositoryAsync(tenantId);
        if (tenantRepository == null)
        {
            logger.LogWarning("OIDC tenant resolution: tenant '{TenantId}' not found", tenantId);
            return false;
        }

        context.Items[InfrastructureCommon.TenantRepositoryName] = tenantRepository;
        context.Items[InfrastructureCommon.TenantIdName] = tenantRepository.TenantId;

        logger.LogDebug("OIDC tenant resolved to '{TenantId}' for {Path}", tenantRepository.TenantId, path);
        return false;
    }

    /// <summary>
    /// Marks the authorization code of the authorize response with the tenant (AB#7892, <see cref="OidcTenantMarker" />).
    /// Supports redirects (<c>response_mode=query</c> or <c>fragment</c>, code in the Location header — OpenIddict emits
    /// 302 Found or 303 See Other depending on response mode/handler) and 200 HTML responses
    /// (<c>response_mode=form_post</c>, code in a hidden form field). Returns the rewritten body for form_post,
    /// otherwise <c>null</c> (the Location header is rewritten in place).
    /// </summary>
    private byte[]? MarkAuthorizationCode(HttpContext context, MemoryStream responseBody, string tenantId)
    {
        if (context.Response.StatusCode is StatusCodes.Status302Found or StatusCodes.Status303SeeOther)
        {
            var location = context.Response.Headers.Location.ToString();
            var marked = MarkCodeInRedirectUri(location, tenantId);
            if (marked != null)
            {
                context.Response.Headers.Location = marked;
                logger.LogDebug("Marked authorization code with tenant '{TenantId}' (response status {StatusCode})",
                    tenantId, context.Response.StatusCode);
            }

            return null;
        }

        if (context.Response.StatusCode == StatusCodes.Status200OK)
        {
            var rewritten = MarkCodeInFormPostBody(responseBody, tenantId);
            if (rewritten != null)
            {
                logger.LogDebug("Marked authorization code with tenant '{TenantId}' (form_post)", tenantId);
            }

            return rewritten;
        }

        return null;
    }

    /// <summary>
    /// Resolves the tenant for <c>/connect/deviceverification</c> from the tenant hint the device page
    /// sends (<c>acr_values=tenant:{tenantId}</c>, query on GET, form body on POST; AB#7891). Without a
    /// hint the request stays on the system tenant, which is right for system-tenant device logins.
    /// </summary>
    internal async Task<string?> ResolveTenantForDeviceVerificationAsync(HttpContext context)
    {
        var tenantId = ExtractTenantFromAcrValues(context);

        if (string.IsNullOrEmpty(tenantId) && context.Request.HasFormContentType)
        {
            context.Request.EnableBuffering();
            try
            {
                tenantId = await ExtractTenantFromFormAcrValuesAsync(context);
            }
            finally
            {
                context.Request.Body.Position = 0;
            }
        }

        if (!string.IsNullOrEmpty(tenantId))
        {
            logger.LogDebug("Resolved tenant '{TenantId}' from the tenant hint for /connect/deviceverification",
                tenantId);
            return tenantId;
        }

        logger.LogDebug("No tenant hint on /connect/deviceverification — using the system tenant");
        return null;
    }

    /// <summary>
    /// Resolves the tenant for a <c>/connect/token</c> request by reading the authorization code,
    /// device code or refresh token from the form body.
    /// </summary>
    internal async Task<string?> ResolveTenantFromTokenRequestAsync(HttpContext context)
    {
        context.Request.EnableBuffering();

        try
        {
            var form = await context.Request.ReadFormAsync();

            var grantType = form["grant_type"].FirstOrDefault();

            if (string.Equals(grantType, "authorization_code", StringComparison.Ordinal))
            {
                // AB#7892: the code carries its tenant (marked on /connect/authorize), so any replica and a
                // restarted process resolve it. The marker is removed before OpenIddict reads the form.
                var markedCode = form["code"].FirstOrDefault();
                if (OidcTenantMarker.TryDecode(markedCode, out var codeTenantId, out var code))
                {
                    ReplaceFormValue(context, form, "code", code);
                    logger.LogDebug("Resolved tenant '{TenantId}' from authorization code for /connect/token",
                        codeTenantId);
                    return codeTenantId;
                }

                // An unmarked code was issued before AB#7892 (or is not ours). The system tenant is the
                // only safe choice: a code of another tenant is unknown in its token store and rejected.
                logger.LogWarning(
                    "Authorization code on /connect/token carries no tenant marker — user/client lookups will use system tenant");
            }
            else if (string.Equals(grantType, "urn:ietf:params:oauth:grant-type:device_code", StringComparison.Ordinal))
            {
                // AB#7891: the tenant travels inside the device_code (OidcTenantMarker), so any
                // replica — also one started after the device authorization — resolves it. The marker
                // is removed before OpenIddict reads the form.
                var markedDeviceCode = form["device_code"].FirstOrDefault();
                if (OidcTenantMarker.TryDecode(markedDeviceCode, out var deviceTenantId, out var deviceCode))
                {
                    ReplaceFormValue(context, form, "device_code", deviceCode);
                    logger.LogDebug("Resolved tenant '{TenantId}' from device code for /connect/token",
                        deviceTenantId);
                    return deviceTenantId;
                }

                // A client that names its tenant itself (acr_values) keeps working with an unmarked code.
                var acrDeviceTenantId = ParseTenantFromAcrValues(form["acr_values"].ToString());
                if (!string.IsNullOrEmpty(acrDeviceTenantId))
                {
                    logger.LogDebug("Resolved tenant '{TenantId}' from acr_values for device code on /connect/token",
                        acrDeviceTenantId);
                    return acrDeviceTenantId;
                }

                logger.LogDebug(
                    "Device code on /connect/token carries no tenant marker — user/client lookups use the system tenant");
            }
            else if (string.Equals(grantType, "client_credentials", StringComparison.Ordinal))
            {
                // Client credentials grant: tenant is specified via acr_values=tenant:{tenantId}
                // in the form body (no user context, no authorization code).
                var acrTenantId = ParseTenantFromAcrValues(form["acr_values"].ToString());
                if (!string.IsNullOrEmpty(acrTenantId))
                {
                    logger.LogDebug(
                        "Resolved tenant '{TenantId}' from acr_values for client_credentials on /connect/token",
                        acrTenantId);
                    return acrTenantId;
                }

                logger.LogWarning(
                    "No acr_values on /connect/token for client_credentials — client lookup will use system tenant");
            }
            else if (string.Equals(grantType, "urn:ietf:params:oauth:grant-type:token-exchange",
                         StringComparison.Ordinal))
            {
                // RFC 8693 Token Exchange (AB#4338): the target tenant (B) is specified via
                // acr_values=tenant:{tenantId} in the form body, exactly like client_credentials.
                // Wiring the B tenant repository into HttpContext.Items here is what lets
                // TenantExchangeGrantValidator re-resolve the user's roles in B (and lets the
                // minted token's per-tenant stores stamp tenant_id=B). The validator additionally
                // asserts the resolved tenant equals the requested B and fails closed otherwise.
                var acrTenantId = ParseTenantFromAcrValues(form["acr_values"].ToString());
                if (!string.IsNullOrEmpty(acrTenantId))
                {
                    logger.LogDebug(
                        "Resolved tenant '{TenantId}' from acr_values for token-exchange on /connect/token",
                        acrTenantId);
                    return acrTenantId;
                }

                logger.LogWarning(
                    "No acr_values on /connect/token for token-exchange — token exchange will be rejected (no target tenant)");
            }
            else if (string.Equals(grantType, DelegationConstants.OnBehalfOfGrantType, StringComparison.Ordinal))
            {
                // Delegation / on-behalf-of (AB#5026): the tenant is specified via
                // acr_values=tenant:{tenantId} in the form body, exactly like client_credentials and
                // token-exchange. This branch is MANDATORY, not cosmetic: without it an unknown
                // grant type falls through to `return null`, no tenant is wired into
                // HttpContext.Items, and every per-tenant store — the client store resolving the
                // service account, the user store resolving the subject, and both role stores —
                // silently reads the SYSTEM tenant instead of the requested one, producing an
                // intersection over the wrong catalogues entirely. OnBehalfOfGrantValidator
                // additionally asserts the resolved tenant equals the requested one and fails closed.
                var acrTenantId = ParseTenantFromAcrValues(form["acr_values"].ToString());
                if (!string.IsNullOrEmpty(acrTenantId))
                {
                    logger.LogDebug(
                        "Resolved tenant '{TenantId}' from acr_values for on-behalf-of on /connect/token",
                        acrTenantId);
                    return acrTenantId;
                }

                logger.LogWarning(
                    "No acr_values on /connect/token for on-behalf-of — delegation will be rejected (no target tenant)");
            }
            else if (string.Equals(grantType, ImpersonationConstants.ImpersonationGrantType,
                         StringComparison.Ordinal))
            {
                // Impersonation (AB#5114): the tenant is specified via acr_values=tenant:{tenantId}
                // in the form body, exactly like client_credentials and on-behalf-of. As with the
                // delegation branch above, this is MANDATORY: without it the request falls through
                // to `return null`, no tenant is wired into HttpContext.Items, and the client
                // lookups plus the MayActAs edge check silently run against the SYSTEM tenant.
                // ImpersonationProcessor additionally asserts the resolved tenant equals the
                // requested one and fails closed.
                var acrTenantId = ParseTenantFromAcrValues(form["acr_values"].ToString());
                if (!string.IsNullOrEmpty(acrTenantId))
                {
                    logger.LogDebug(
                        "Resolved tenant '{TenantId}' from acr_values for impersonation on /connect/token",
                        acrTenantId);
                    return acrTenantId;
                }

                logger.LogWarning(
                    "No acr_values on /connect/token for impersonation — impersonation will be rejected (no target tenant)");
            }
            else if (string.Equals(grantType, "refresh_token", StringComparison.Ordinal))
            {
                // AB#7892: the refresh token carries its tenant (marked on every /connect/token response),
                // so clients without acr_values (octo-sdk without a tenant, services) keep refreshing on any
                // replica and after a restart. The marker names the token store the token lives in and wins
                // over acr_values; the marker is removed before OpenIddict reads the form.
                var markedRefreshToken = form["refresh_token"].FirstOrDefault();
                var acrTenantId = ParseTenantFromAcrValues(form["acr_values"].ToString());
                if (OidcTenantMarker.TryDecode(markedRefreshToken, out var refreshTenantId, out var refreshToken))
                {
                    ReplaceFormValue(context, form, "refresh_token", refreshToken);
                    if (!string.IsNullOrEmpty(acrTenantId) &&
                        !string.Equals(acrTenantId, refreshTenantId, StringComparison.OrdinalIgnoreCase))
                    {
                        logger.LogWarning(
                            "acr_values tenant '{AcrTenantId}' differs from the refresh token's tenant '{TenantId}' on /connect/token — using the token's tenant",
                            acrTenantId, refreshTenantId);
                    }

                    logger.LogDebug("Resolved tenant '{TenantId}' from refresh token for /connect/token",
                        refreshTenantId);
                    return refreshTenantId;
                }

                // An unmarked refresh token was issued before AB#7892. The SPA names its tenant with
                // acr_values=tenant:{tenantId} on every refresh.
                if (!string.IsNullOrEmpty(acrTenantId))
                {
                    logger.LogDebug(
                        "Resolved tenant '{TenantId}' from acr_values for refresh_token on /connect/token",
                        acrTenantId);
                    return acrTenantId;
                }

                logger.LogDebug(
                    "Refresh token on /connect/token carries no tenant marker and no acr_values — user/client lookups will use system tenant");
            }
        }
        finally
        {
            context.Request.Body.Position = 0;
        }

        return null;
    }

    /// <summary>
    /// Marks the <c>refresh_token</c> of a successful <c>/connect/token</c> JSON response with the tenant
    /// (AB#7892), so the next refresh resolves the tenant on any replica. Returns the rewritten body, or
    /// <c>null</c> when the response carries no refresh token.
    /// </summary>
    internal byte[]? MarkRefreshTokenInTokenResponse(MemoryStream responseBody, string tenantId)
    {
        try
        {
            if (JsonNode.Parse(responseBody.ToArray()) is JsonObject body &&
                body["refresh_token"] is JsonValue refreshTokenValue &&
                refreshTokenValue.TryGetValue<string>(out var refreshToken) &&
                !string.IsNullOrEmpty(refreshToken))
            {
                body["refresh_token"] = OidcTenantMarker.Encode(tenantId, refreshToken);
                logger.LogDebug("Marked refresh token with tenant '{TenantId}'", tenantId);
                return Encoding.UTF8.GetBytes(body.ToJsonString(DeviceResponseJsonOptions));
            }
        }
        catch (JsonException)
        {
            // Non-JSON response; leave it alone
        }

        return null;
    }

    /// <summary>
    /// Removes the tenant marker of the <c>token</c> form field (<c>/connect/revocation</c>,
    /// <c>/connect/introspect</c>; AB#7892) and returns its tenant, or <c>null</c> for an unmarked token.
    /// </summary>
    private static async Task<string?> UnmarkFormTokenAsync(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            return null;
        }

        context.Request.EnableBuffering();
        try
        {
            var form = await context.Request.ReadFormAsync();
            if (!OidcTenantMarker.TryDecode(form["token"].FirstOrDefault(), out var tenantId, out var token))
            {
                return null;
            }

            ReplaceFormValue(context, form, "token", token);
            return tenantId;
        }
        finally
        {
            context.Request.Body.Position = 0;
        }
    }

    /// <summary>
    /// Marks the <c>code</c> parameter of an OAuth2 redirect URI (query or fragment) with the tenant.
    /// Returns <c>null</c> when the URI carries no code.
    /// </summary>
    internal static string? MarkCodeInRedirectUri(string? locationUri, string tenantId)
    {
        if (string.IsNullOrEmpty(locationUri))
        {
            return null;
        }

        var fragmentIndex = locationUri.IndexOf('#');
        var queryIndex = locationUri.IndexOf('?');
        if (queryIndex >= 0 && (fragmentIndex < 0 || queryIndex < fragmentIndex))
        {
            var queryEnd = fragmentIndex < 0 ? locationUri.Length : fragmentIndex;
            var marked = MarkCodeInParameters(locationUri[(queryIndex + 1)..queryEnd], tenantId);
            if (marked != null)
            {
                return locationUri[..(queryIndex + 1)] + marked + locationUri[queryEnd..];
            }
        }

        if (fragmentIndex >= 0)
        {
            var marked = MarkCodeInParameters(locationUri[(fragmentIndex + 1)..], tenantId);
            if (marked != null)
            {
                return locationUri[..(fragmentIndex + 1)] + marked;
            }
        }

        return null;
    }

    /// <summary>
    /// Marks the <c>code</c> entry of an <c>application/x-www-form-urlencoded</c> parameter string; every other
    /// entry stays byte for byte. Returns <c>null</c> when there is no code.
    /// </summary>
    private static string? MarkCodeInParameters(string parameters, string tenantId)
    {
        var parts = parameters.Split('&');
        for (var i = 0; i < parts.Length; i++)
        {
            if (!parts[i].StartsWith("code=", StringComparison.Ordinal))
            {
                continue;
            }

            var code = Uri.UnescapeDataString(parts[i]["code=".Length..].Replace('+', ' '));
            if (string.IsNullOrEmpty(code))
            {
                return null;
            }

            parts[i] = "code=" + Uri.EscapeDataString(OidcTenantMarker.Encode(tenantId, code));
            return string.Join('&', parts);
        }

        return null;
    }

    /// <summary>
    /// Marks the hidden <c>code</c> field of an OAuth2 <c>response_mode=form_post</c> HTML response with the tenant.
    /// Returns <c>null</c> when the body carries no code.
    /// </summary>
    internal static byte[]? MarkCodeInFormPostBody(MemoryStream responseBody, string tenantId)
    {
        var html = Encoding.UTF8.GetString(responseBody.ToArray());
        var match = FormPostCodePattern.Match(html);
        if (!match.Success)
        {
            return null;
        }

        // The tenant id holds only [A-Za-z0-9_-] and the separator ':' — nothing that needs HTML encoding.
        var group = match.Groups[1];
        var marked = html[..group.Index] + OidcTenantMarker.Encode(tenantId, group.Value) +
                     html[(group.Index + group.Length)..];
        return Encoding.UTF8.GetBytes(marked);
    }

    /// <summary>
    /// Scans request cookies for tenant-scoped identity session cookies
    /// (<c>.AspNetCore.Identity.Application.{tenantId}</c>) to detect existing sessions.
    /// Returns the list of tenant IDs that have active session cookies.
    /// </summary>
    private static List<string> FindTenantIdsFromSessionCookies(HttpContext context)
    {
        const string cookiePrefix = ".AspNetCore.Identity.Application.";
        var tenantIds = new List<string>();

        foreach (var cookieName in context.Request.Cookies.Keys)
        {
            if (!cookieName.StartsWith(cookiePrefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var suffix = cookieName[cookiePrefix.Length..];

            // Skip chunked cookie segments (e.g., ".AspNetCore.Identity.Application.tenantC1")
            // Real tenant IDs don't end with C followed by digits
            if (suffix.Length > 1 && suffix[^1] is >= '0' and <= '9' && suffix[^2..^1] == "C")
            {
                // Might be a chunk — extract tenant without the chunk suffix
                var chunkIndex = suffix.LastIndexOf('C');
                if (chunkIndex > 0 && suffix[(chunkIndex + 1)..].All(char.IsDigit))
                {
                    suffix = suffix[..chunkIndex];
                }
            }

            if (!string.IsNullOrEmpty(suffix) && !tenantIds.Contains(suffix, StringComparer.OrdinalIgnoreCase))
            {
                tenantIds.Add(suffix);
            }
        }

        return tenantIds;
    }

    /// <summary>
    /// Replaces one form field of the current request for everything downstream (OpenIddict reads the
    /// form through <see cref="IFormFeature" />). The raw body is re-encoded as well, so a reader of the
    /// body sees the same values. Used to strip the tenant marker from the device code (AB#7891).
    /// </summary>
    internal static void ReplaceFormValue(HttpContext context, IFormCollection form, string key, string value)
    {
        var fields = new Dictionary<string, StringValues>(StringComparer.Ordinal);
        foreach (var (fieldKey, fieldValue) in form)
        {
            fields[fieldKey] = fieldValue;
        }

        fields[key] = value;

        var encoded = string.Join('&', fields.SelectMany(field => field.Value.Select(v =>
            $"{Uri.EscapeDataString(field.Key)}={Uri.EscapeDataString(v ?? string.Empty)}")));
        var bytes = Encoding.UTF8.GetBytes(encoded);

        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;
        context.Features.Set<IFormFeature>(new FormFeature(new FormCollection(fields)));
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

    /// <summary>
    /// Reads the tenant (or the AB#5311 discovery scope) marked into the <c>request_uri</c> of a
    /// <c>/connect/authorize?request_uri=...</c> call and removes the marker from the query, so OpenIddict sees
    /// the request_uri it issued on <c>/connect/par</c> (AB#7892).
    /// </summary>
    private (string? TenantId, string? ScopeTenantId) UnmarkRequestUri(HttpContext context)
    {
        if (!context.Request.Query.TryGetValue("request_uri", out var requestUriValues) ||
            !OidcTenantMarker.TryDecodeRequestUri(requestUriValues.FirstOrDefault(), out var tenantId,
                out var scopeTenantId, out var requestUri))
        {
            return (null, null);
        }

        var query = QueryHelpers.ParseQuery(context.Request.QueryString.Value);
        query["request_uri"] = requestUri;
        var builder = new QueryBuilder();
        foreach (var (key, values) in query)
        {
            foreach (var value in values)
            {
                builder.Add(key, value ?? string.Empty);
            }
        }

        context.Request.QueryString = builder.ToQueryString();

        if (tenantId != null)
        {
            logger.LogDebug("Resolved tenant '{TenantId}' from PAR request_uri on /connect/authorize", tenantId);
        }
        else
        {
            logger.LogDebug("Restored discovery scope '{ScopeTenantId}' from PAR request_uri on /connect/authorize",
                scopeTenantId);
        }

        return (tenantId, scopeTenantId);
    }

    /// <summary>
    /// Marks the <c>request_uri</c> of a successful <c>/connect/par</c> JSON response (RFC 9126) with the tenant —
    /// or, for a scope-only PAR, with the discovery scope (AB#5311) — so the follow-up
    /// <c>/connect/authorize?request_uri=...</c> recovers it on any replica (AB#7892). Returns the rewritten body,
    /// or <c>null</c> when nothing was marked.
    /// </summary>
    internal byte[]? MarkRequestUriInParResponse(MemoryStream responseBody, string? tenantId, string? scopeTenantId)
    {
        try
        {
            if (JsonNode.Parse(responseBody.ToArray()) is JsonObject body &&
                body["request_uri"] is JsonValue requestUriValue &&
                requestUriValue.TryGetValue<string>(out var requestUri) &&
                !string.IsNullOrEmpty(requestUri))
            {
                var marked = OidcTenantMarker.EncodeRequestUri(requestUri, tenantId, scopeTenantId);
                if (marked == null)
                {
                    logger.LogWarning("PAR request_uri has an unexpected form and was not marked with the tenant");
                    return null;
                }

                body["request_uri"] = marked;
                logger.LogDebug("Marked PAR request_uri with tenant '{TenantId}' / discovery scope '{ScopeTenantId}'",
                    tenantId ?? "-", scopeTenantId ?? "-");
                return Encoding.UTF8.GetBytes(body.ToJsonString(DeviceResponseJsonOptions));
            }
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "Failed to mark the PAR request_uri with the tenant");
        }

        return null;
    }

    internal static string? ParseTenantFromAcrValues(string acrValues)
    {
        return ParseAcrValue(acrValues, "tenant:");
    }

    /// <summary>
    ///     AB#5311: the discovery scope an app host passes as <c>acr_values=tenant_scope:{id}</c>.
    ///     A second, space-separated entry next to <c>tenant:</c>; <c>null</c> when absent.
    /// </summary>
    internal static string? ParseScopeFromAcrValues(string acrValues)
    {
        return ParseAcrValue(acrValues, "tenant_scope:");
    }

    private static string? ParseAcrValue(string acrValues, string prefix)
    {
        var values = acrValues.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var value in values)
        {
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                var tenantId = value.Substring(prefix.Length);
                if (!string.IsNullOrEmpty(tenantId))
                {
                    return tenantId;
                }
            }
        }

        return null;
    }

    private static string? ExtractScopeFromAcrValues(HttpContext context)
    {
        return context.Request.Query.TryGetValue("acr_values", out var acrValues)
            ? ParseScopeFromAcrValues(acrValues.ToString())
            : null;
    }

    private static async Task<string?> ExtractScopeFromFormAcrValuesAsync(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            return null;
        }

        var form = await context.Request.ReadFormAsync();
        return form.TryGetValue("acr_values", out var acrValues)
            ? ParseScopeFromAcrValues(acrValues.ToString())
            : null;
    }

    /// <summary>
    ///     HttpContext.Items key under which a scope-only <c>/connect/par</c> hands its discovery
    ///     scope to the response marking (AB#5311, AB#7892).
    /// </summary>
    private const string ParDiscoveryScopeItem = "octo.oidc.par.tenant_scope";

    /// <summary>
    ///     The <c>/tenant-discovery</c> redirect. The scope travels as its own query parameter so
    ///     the SPA does not have to parse it out of the returnUrl's <c>acr_values</c>; the returnUrl
    ///     keeps the scope entry too, and the SPA appends <c>tenant:{id}</c> next to it.
    /// </summary>
    internal static string BuildDiscoveryUrl(string authorizeUrl, string? scopeTenantId)
    {
        var url = $"/tenant-discovery?returnUrl={Uri.EscapeDataString(authorizeUrl)}";
        return string.IsNullOrEmpty(scopeTenantId)
            ? url
            : $"{url}&scopeTenantId={Uri.EscapeDataString(scopeTenantId)}";
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
    /// Extracts the <c>tenant_id</c> claim from the Bearer access token in the Authorization header.
    /// Used for endpoints like <c>/connect/userinfo</c>, <c>/connect/introspect</c>, and
    /// <c>/connect/revocation</c> that receive an access token but have no tenant route segment.
    /// </summary>
    private string? ExtractTenantFromBearerToken(HttpContext context)
    {
        var authorization = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authorization) ||
            !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var token = authorization["Bearer ".Length..].Trim();
        return ExtractTenantFromJwtPayload(token);
    }

    /// <summary>
    /// Extracts the <c>tenant_id</c> claim from the JWT payload without signature verification.
    /// The token has already been validated by OpenIddict when it was issued; we only need
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
    /// Writes the rewritten device authorization response without escaping URL characters
    /// (<c>&amp;</c>, <c>+</c>) as <c>\uXXXX</c>, so the body stays byte-for-byte like OpenIddict's apart
    /// from the changed values.
    /// </summary>
    private static readonly JsonSerializerOptions DeviceResponseJsonOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Rewrites the device authorization JSON response for the resolved tenant: marks the
    /// <c>device_code</c> with the tenant (AB#7891) and points <c>verification_uri</c> /
    /// <c>verification_uri_complete</c> to the tenant's device page.
    /// </summary>
    internal byte[]? RewriteDeviceAuthorizationResponse(MemoryStream responseBody, string tenantId)
    {
        var json = Encoding.UTF8.GetString(responseBody.ToArray());
        var rewrittenUrls = RewriteDeviceVerificationUrls(json, tenantId);
        var withUrls = rewrittenUrls ?? json;

        try
        {
            if (JsonNode.Parse(withUrls) is JsonObject body &&
                body["device_code"] is JsonValue deviceCodeValue &&
                deviceCodeValue.TryGetValue<string>(out var deviceCode) &&
                !string.IsNullOrEmpty(deviceCode))
            {
                body["device_code"] = OidcTenantMarker.Encode(tenantId, deviceCode);
                logger.LogDebug("Marked device code with tenant '{TenantId}'", tenantId);
                return Encoding.UTF8.GetBytes(body.ToJsonString(DeviceResponseJsonOptions));
            }
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "Failed to mark the device code with the tenant");
        }

        return rewrittenUrls == null ? null : Encoding.UTF8.GetBytes(rewrittenUrls);
    }

    /// <summary>
    /// Rewrites <c>verification_uri</c> and <c>verification_uri_complete</c> in the device authorization
    /// JSON response to use the resolved tenant ID instead of the system tenant prefix.
    /// Returns <c>null</c> when nothing had to change.
    /// </summary>
    private string? RewriteDeviceVerificationUrls(string json, string tenantId)
    {
        try
        {
            var systemTenantId = octoSystemConfiguration.Value.SystemTenantId;
            var systemPath = $"/{systemTenantId}/device";
            var tenantPath = $"/{tenantId}/device";

            // OpenIddict (AB#4993) advertises its fixed end-user verification endpoint; the human
            // UI is the Angular device page, so point verification_uri(_complete) there and
            // translate the query parameter to the SPA's userCode convention.
            const string openIddictVerificationPath = "/connect/deviceverification";
            if (json.Contains(openIddictVerificationPath, StringComparison.OrdinalIgnoreCase))
            {
                var rewrittenJson = json
                    .Replace(openIddictVerificationPath, tenantPath, StringComparison.OrdinalIgnoreCase)
                    .Replace("user_code=", "userCode=", StringComparison.Ordinal);
                logger.LogDebug(
                    "Rewrote device verification URLs from '{VerificationPath}' to '{TenantPath}'",
                    openIddictVerificationPath, tenantPath);
                return rewrittenJson;
            }

            if (!json.Contains(systemPath, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            var rewritten = json.Replace(systemPath, tenantPath, StringComparison.OrdinalIgnoreCase);
            logger.LogDebug(
                "Rewrote device verification URLs from '{SystemPath}' to '{TenantPath}'",
                systemPath, tenantPath);
            return rewritten;
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
