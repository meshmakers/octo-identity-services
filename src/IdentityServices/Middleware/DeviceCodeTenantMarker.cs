using Meshmakers.Octo.Services.Infrastructure.Routing;

namespace Meshmakers.Octo.Backend.IdentityServices.Middleware;

/// <summary>
///     Carries the tenant of a device authorization inside the <c>device_code</c> the client receives, so the
///     <c>/connect/token</c> poll can recover the tenant without server-side state (AB#7891).
/// </summary>
/// <remarks>
///     <para>
///         The wire value is <c>{tenantId}:{deviceCode}</c>, where <c>deviceCode</c> is the value OpenIddict issued. The
///         marker is added on the <c>/connect/deviceauthorization</c> response and removed again from the
///         <c>/connect/token</c> form before OpenIddict sees it, so OpenIddict only ever handles its own value. RFC 8628
///         makes the device code opaque to the client; octo-cli and other clients pass it back unchanged.
///     </para>
///     <para>
///         <b>Why no signature.</b> The prefix only selects the tenant whose token store OpenIddict validates the device
///         code against. Device codes are persisted per tenant, so a changed prefix makes OpenIddict look in a store that
///         does not hold the code and answer <c>invalid_grant</c> — the same as any unknown code. Nothing is granted on the
///         prefix alone.
///     </para>
///     <para>
///         The separator <c>:</c> can never be part of a tenant id (ASCII letters, digits, <c>-</c>, <c>_</c>; see
///         <see cref="TenantIdRouteConstraint.IsWellFormed" />), so the first <c>:</c> always ends the tenant id.
///     </para>
/// </remarks>
internal static class DeviceCodeTenantMarker
{
    internal const char Separator = ':';

    /// <summary>Prefixes <paramref name="deviceCode" /> with <paramref name="tenantId" />.</summary>
    internal static string Encode(string tenantId, string deviceCode) => $"{tenantId}{Separator}{deviceCode}";

    /// <summary>
    ///     Splits a marked device code into tenant id and the original device code. Returns <c>false</c> for a value
    ///     without a well-formed tenant prefix (e.g. a code issued before AB#7891 or for a request without tenant).
    /// </summary>
    internal static bool TryDecode(string? markedDeviceCode, out string tenantId, out string deviceCode)
    {
        tenantId = string.Empty;
        deviceCode = string.Empty;

        if (string.IsNullOrEmpty(markedDeviceCode))
        {
            return false;
        }

        var separatorIndex = markedDeviceCode.IndexOf(Separator);
        if (separatorIndex <= 0 || separatorIndex == markedDeviceCode.Length - 1)
        {
            return false;
        }

        var candidateTenant = markedDeviceCode[..separatorIndex];
        if (!TenantIdRouteConstraint.IsWellFormed(candidateTenant))
        {
            return false;
        }

        tenantId = candidateTenant;
        deviceCode = markedDeviceCode[(separatorIndex + 1)..];
        return true;
    }
}
