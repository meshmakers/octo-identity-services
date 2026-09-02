using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Protocol;

/// <summary>
///     OIDC Session Management check-session iframe, served at the pre-migration path
///     <c>/connect/checksession</c> that RPs already have cached from discovery.
///     RPs embed this page in a hidden iframe and post <c>"client_id session_state"</c> messages;
///     the script recomputes the session-state hash from the browser's
///     <c>idsrv.session[.tenant]</c> cookies and answers <c>unchanged</c> / <c>changed</c> /
///     <c>error</c>. A logout deletes the cookie, so every polling tab receives
///     <c>changed</c> and can end its own session. The hash formula must stay in sync with
///     <c>OctoSessionStateHandler.ComputeSessionState</c>.
/// </summary>
[ApiController]
public class CheckSessionController : ControllerBase
{
    private const string Html = """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>Check Session IFrame</title></head>
        <body>
        <script>
        (function () {
            'use strict';

            function base64Url(buffer) {
                var bytes = new Uint8Array(buffer);
                var binary = '';
                for (var i = 0; i < bytes.length; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            }

            function sessionCookieValues() {
                var values = [];
                var pairs = document.cookie ? document.cookie.split('; ') : [];
                for (var i = 0; i < pairs.length; i++) {
                    var eq = pairs[i].indexOf('=');
                    if (eq < 0) { continue; }
                    var name = pairs[i].substring(0, eq);
                    if (name === 'idsrv.session' || name.indexOf('idsrv.session.') === 0) {
                        values.push(decodeURIComponent(pairs[i].substring(eq + 1)));
                    }
                }
                return values;
            }

            window.addEventListener('message', function (e) {
                var reply = function (result) { e.source.postMessage(result, e.origin); };

                if (typeof e.data !== 'string') { reply('error'); return; }
                var space = e.data.lastIndexOf(' ');
                if (space < 1) { reply('error'); return; }
                var clientId = e.data.substring(0, space);
                var sessionState = e.data.substring(space + 1);
                var dot = sessionState.lastIndexOf('.');
                if (dot < 1) { reply('error'); return; }
                var hash = sessionState.substring(0, dot);
                var salt = sessionState.substring(dot + 1);

                var candidates = sessionCookieValues();
                if (candidates.length === 0) { reply('changed'); return; }

                var checks = candidates.map(function (opbs) {
                    var data = clientId + ' ' + e.origin + ' ' + opbs + ' ' + salt;
                    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(data))
                        .then(function (digest) { return base64Url(digest) === hash; });
                });

                Promise.all(checks)
                    .then(function (results) {
                        reply(results.indexOf(true) >= 0 ? 'unchanged' : 'changed');
                    })
                    .catch(function () { reply('error'); });
            }, false);
        })();
        </script>
        </body>
        </html>
        """;

    [HttpGet("/connect/checksession")]
    public ContentResult Index() => Content(Html, "text/html; charset=utf-8");
}
