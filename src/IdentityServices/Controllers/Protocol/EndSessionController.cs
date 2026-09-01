using System.Text;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Protocol;

/// <summary>
///     OpenIddict end-session endpoint passthrough (AB#4995): packages the validated end-session
///     request (client, post-logout redirect, state, session) into a self-contained data-protected
///     <c>logoutId</c> and hands the flow to the tenant's Angular logout page — the exact flow
///     Duende drove via its logout message store + <c>TenantLoginRedirectMiddleware</c>. The SPA
///     completes the logout via <c>AuthApiController</c> (sign-out, session/token revocation) and
///     then navigates to the post-logout redirect URI.
/// </summary>
[ApiController]
[AllowAnonymous]
[IgnoreAntiforgeryToken]
public class EndSessionController(
    IOctoClientStore clientStore,
    IOctoInteractionService interactionService) : ControllerBase
{
    [HttpGet("~/connect/endsession")]
    [HttpPost("~/connect/endsession")]
    public async Task<IActionResult> EndSession()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

        // OpenIddict has already validated id_token_hint and post_logout_redirect_uri against
        // the client registration before invoking the passthrough.
        var tenantId = HttpContext.Items[InfrastructureCommon.TenantIdName] as string ?? "System";

        string? clientId = request.ClientId;
        string? subjectId = null;
        string? sessionId = null;

        if (!string.IsNullOrEmpty(request.IdTokenHint))
        {
            // Payload-only read: the hint was already validated by OpenIddict; we only recover
            // addressing information (client/subject/session) for the logout context.
            var handler = new JsonWebTokenHandler();
            if (handler.CanReadToken(request.IdTokenHint))
            {
                var idToken = handler.ReadJsonWebToken(request.IdTokenHint);
                clientId ??= idToken.Audiences.FirstOrDefault();
                subjectId = idToken.TryGetClaim(Claims.Subject, out var sub) ? sub.Value : null;
                sessionId = idToken.TryGetClaim("sid", out var sid) ? sid.Value : null;
            }
        }

        string? clientName = null;
        if (!string.IsNullOrEmpty(clientId))
        {
            var client = await clientStore.FindRtClientByIdAsync(clientId);
            clientName = client?.ClientName ?? clientId;
        }

        var logoutId = interactionService.CreateLogoutId(new OctoLogoutContext
        {
            ClientId = clientId,
            ClientName = clientName,
            PostLogoutRedirectUri = request.PostLogoutRedirectUri,
            State = request.State,
            SubjectId = subjectId,
            SessionId = sessionId,
            TenantId = tenantId
        });

        return Redirect($"/{tenantId}/logout?logoutId={Uri.EscapeDataString(logoutId)}");
    }

    /// <summary>
    ///     Front-channel logout notification page (replaces Duende's
    ///     <c>/connect/endsession/callback</c>): renders one hidden iframe per enabled client
    ///     that registered a <c>FrontChannelLogoutUri</c>, carrying <c>iss</c> + <c>sid</c>.
    ///     The session's exact client list is not tracked (Duende did) — notifying every
    ///     registered front-channel client is a safe superset: clients without a session
    ///     treat the notification as a no-op.
    /// </summary>
    [HttpGet("~/connect/endsession/callback")]
    public async Task<IActionResult> FrontChannelLogoutCallback([FromQuery] string? sid)
    {
        var issuer = $"{Request.Scheme}://{Request.Host}{Request.PathBase}/";

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html><head><meta http-equiv='Cache-Control' content='no-store'/>")
            .Append("<title>Logout</title></head><body>");

        foreach (var client in await clientStore.GetClients())
        {
            if (!client.Enabled || string.IsNullOrEmpty(client.FrontChannelLogoutUri))
            {
                continue;
            }

            var uri = client.FrontChannelLogoutUri;
            if (client.FrontChannelLogoutSessionRequired == true)
            {
                var separator = uri.Contains('?') ? "&" : "?";
                uri = $"{uri}{separator}iss={Uri.EscapeDataString(issuer)}&sid={Uri.EscapeDataString(sid ?? string.Empty)}";
            }

            html.Append("<iframe style='display:none' src='")
                .Append(System.Net.WebUtility.HtmlEncode(uri))
                .Append("'></iframe>");
        }

        html.Append("</body></html>");
        return Content(html.ToString(), "text/html", Encoding.UTF8);
    }
}
