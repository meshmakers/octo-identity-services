using Meshmakers.Octo.Services.Infrastructure.Routing;

namespace Meshmakers.Octo.Backend.IdentityServices.Middleware;

/// <summary>
///     Carries the tenant of an OIDC value inside the value the client receives, so a later request that sends the
///     value back can recover the tenant without server-side state — on any identity replica and after a restart.
///     Used for device codes (AB#7891), authorization codes, refresh tokens and PAR request_uris (AB#7892).
/// </summary>
/// <remarks>
///     <para>
///         The wire value is <c>{tenantId}:{value}</c>, where <c>value</c> is what OpenIddict issued. The marker is added
///         on the response that hands the value to the client and removed again from the request before OpenIddict sees
///         it, so OpenIddict only ever handles its own value. Codes and tokens are opaque to clients (RFC 6749 §1.4/§1.5,
///         RFC 8628 §3.2); octo-cli, octo-sdk and the SPAs pass them back unchanged.
///     </para>
///     <para>
///         <b>Why no signature.</b> The prefix only selects the tenant whose token store OpenIddict validates the value
///         against. Codes, refresh tokens and PAR request tokens are persisted per tenant (<c>RtOAuthToken</c> in the
///         tenant's database), so a changed prefix makes OpenIddict look in a store that does not hold the value and
///         answer <c>invalid_grant</c> (or <c>invalid_request</c> for a request_uri) — the same as any unknown value.
///         Nothing is granted on the prefix alone; a value can never resolve to another tenant.
///     </para>
///     <para>
///         The separator <c>:</c> can never be part of a tenant id (ASCII letters, digits, <c>-</c>, <c>_</c>; see
///         <see cref="TenantIdRouteConstraint.IsWellFormed" />), so the first <c>:</c> always ends the tenant id.
///     </para>
///     <para>
///         <b>PAR request_uris</b> are URNs (<c>urn:ietf:params:oauth:request_uri:{reference}</c>) that already contain
///         <c>:</c>. They keep their URN prefix; the marker sits between prefix and reference
///         (<see cref="EncodeRequestUri" />). A scope-only PAR (AB#5311) names no tenant but a discovery scope, which is
///         carried as <c>{ScopeMarkerPrefix}{scopeTenantId}</c> in the same place — <c>.</c> is not a tenant-id
///         character, so a scope marker can never be read as a tenant.
///     </para>
/// </remarks>
internal static class OidcTenantMarker
{
    internal const char Separator = ':';

    /// <summary>URN prefix of OpenIddict's PAR request_uris (RFC 9126 §2.2).</summary>
    internal const string RequestUriPrefix = "urn:ietf:params:oauth:request_uri:";

    /// <summary>Marks a discovery scope (not a tenant) inside a PAR request_uri (AB#5311).</summary>
    internal const string ScopeMarkerPrefix = "tenant_scope.";

    /// <summary>Prefixes <paramref name="value" /> with <paramref name="tenantId" />.</summary>
    internal static string Encode(string tenantId, string value) => $"{tenantId}{Separator}{value}";

    /// <summary>
    ///     Splits a marked value into tenant id and the original value. Returns <c>false</c> for a value without a
    ///     well-formed tenant prefix (e.g. a value issued before AB#7891/AB#7892 or for a request without tenant).
    /// </summary>
    internal static bool TryDecode(string? markedValue, out string tenantId, out string value)
    {
        tenantId = string.Empty;
        value = string.Empty;

        if (!TrySplit(markedValue, out var candidateTenant, out var rest) ||
            !TenantIdRouteConstraint.IsWellFormed(candidateTenant))
        {
            return false;
        }

        tenantId = candidateTenant;
        value = rest;
        return true;
    }

    /// <summary>
    ///     Marks a PAR request_uri with its tenant or — for a scope-only PAR — its discovery scope. Returns
    ///     <c>null</c> when there is nothing to mark or the value is not an OpenIddict request_uri URN.
    /// </summary>
    internal static string? EncodeRequestUri(string requestUri, string? tenantId, string? scopeTenantId)
    {
        if (!requestUri.StartsWith(RequestUriPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var reference = requestUri[RequestUriPrefix.Length..];
        if (!string.IsNullOrEmpty(tenantId))
        {
            return RequestUriPrefix + Encode(tenantId, reference);
        }

        return string.IsNullOrEmpty(scopeTenantId)
            ? null
            : RequestUriPrefix + Encode(ScopeMarkerPrefix + scopeTenantId, reference);
    }

    /// <summary>
    ///     Splits a marked PAR request_uri into the tenant (or the discovery scope) and the request_uri OpenIddict
    ///     issued. Returns <c>false</c> for an unmarked or foreign value.
    /// </summary>
    internal static bool TryDecodeRequestUri(string? markedRequestUri, out string? tenantId, out string? scopeTenantId,
        out string requestUri)
    {
        tenantId = null;
        scopeTenantId = null;
        requestUri = string.Empty;

        if (markedRequestUri == null || !markedRequestUri.StartsWith(RequestUriPrefix, StringComparison.Ordinal) ||
            !TrySplit(markedRequestUri[RequestUriPrefix.Length..], out var marker, out var reference))
        {
            return false;
        }

        if (marker.StartsWith(ScopeMarkerPrefix, StringComparison.Ordinal))
        {
            var scope = marker[ScopeMarkerPrefix.Length..];
            if (!TenantIdRouteConstraint.IsWellFormed(scope))
            {
                return false;
            }

            scopeTenantId = scope;
        }
        else if (TenantIdRouteConstraint.IsWellFormed(marker))
        {
            tenantId = marker;
        }
        else
        {
            return false;
        }

        requestUri = RequestUriPrefix + reference;
        return true;
    }

    private static bool TrySplit(string? markedValue, out string marker, out string rest)
    {
        marker = string.Empty;
        rest = string.Empty;

        if (string.IsNullOrEmpty(markedValue))
        {
            return false;
        }

        var separatorIndex = markedValue.IndexOf(Separator);
        if (separatorIndex <= 0 || separatorIndex == markedValue.Length - 1)
        {
            return false;
        }

        marker = markedValue[..separatorIndex];
        rest = markedValue[(separatorIndex + 1)..];
        return true;
    }
}
