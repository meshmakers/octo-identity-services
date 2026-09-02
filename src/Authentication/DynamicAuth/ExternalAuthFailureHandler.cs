using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Shared <c>OnRemoteFailure</c> handler for the external OAuth/OIDC schemes (Google,
///     Microsoft, Facebook, Azure Entra ID). Without it a failed remote login — a wrong client
///     secret, a user cancelling on the provider's consent page (<c>access_denied</c>) — bubbles
///     out of <c>RemoteAuthenticationHandler</c> as an unhandled
///     <c>AuthenticationFailureException</c> and renders the developer exception page instead of
///     the SPA error page.
/// </summary>
public static class ExternalAuthFailureHandler
{
    /// <summary>
    ///     Redirects to the tenant's SPA error page with <c>?error=…&amp;errorDescription=…</c>
    ///     (the query shape <c>GetErrorContext</c> understands) and marks the response handled.
    ///     The tenant is derived from the scheme name (<c>{tenant}:{provider}</c>).
    /// </summary>
    public static Task HandleRemoteFailureAsync(RemoteFailureContext context)
    {
        var scheme = context.Scheme.Name;
        var separator = scheme.IndexOf(':');
        var tenantId = separator > 0 ? scheme[..separator] : "system";

        var description = context.Failure?.Message ?? "External login failed";
        context.Response.Redirect(
            $"/{Uri.EscapeDataString(tenantId)}/error" +
            $"?error={Uri.EscapeDataString("external_login_failure")}" +
            $"&errorDescription={Uri.EscapeDataString(description)}");
        context.HandleResponse();
        return Task.CompletedTask;
    }
}
