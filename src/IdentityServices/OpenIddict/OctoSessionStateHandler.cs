using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.WebUtilities;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     OIDC Session Management (Duende parity): appends the <c>session_state</c> parameter to
///     successful authorization responses. RP libraries (angular-oauth2-oidc with
///     <c>sessionChecksEnabled</c>) hand it to the <c>/connect/checksession</c> iframe, which
///     recomputes the hash from the browser's <see cref="SessionCheckCookie" /> — a logout drops
///     the cookie, the hash no longer matches and every polling tab learns the session ended.
/// </summary>
public class OctoSessionStateHandler : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<OctoSessionStateHandler>()
            .SetOrder(int.MinValue + 50_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Only successful front-channel responses carry session_state.
        if (!string.IsNullOrEmpty(context.Response.Error) || string.IsNullOrEmpty(context.Response.Code))
        {
            return default;
        }

        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
        var clientId = context.Request?.ClientId;
        var redirectUri = context.Request?.RedirectUri;
        if (httpContext == null || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri) ||
            !Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
        {
            return default;
        }

        var opBrowserState = SessionCheckCookie.Read(httpContext);
        if (string.IsNullOrEmpty(opBrowserState))
        {
            return default;
        }

        var origin = uri.GetLeftPart(UriPartial.Authority);
        var salt = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        context.Response["session_state"] = ComputeSessionState(clientId, origin, opBrowserState, salt);
        return default;
    }

    /// <summary>
    ///     Hash formula shared with the <c>/connect/checksession</c> iframe script
    ///     (<c>CheckSessionController</c>) — change both together or session checks
    ///     permanently report 'changed'.
    /// </summary>
    internal static string ComputeSessionState(string clientId, string origin, string opBrowserState, string salt)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{clientId} {origin} {opBrowserState} {salt}"));
        return $"{WebEncoders.Base64UrlEncode(hash)}.{salt}";
    }
}
