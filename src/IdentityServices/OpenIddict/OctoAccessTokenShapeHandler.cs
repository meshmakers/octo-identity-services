using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict;

/// <summary>
///     Shapes OpenIddict-generated access tokens to the exact wire format Duende produced, so
///     resource services and the golden baseline
///     (<c>tests/IdentityServices.IntegrationTests/GoldenFiles</c>) cannot tell the difference
///     (AB#4990/AB#4992):
///     <list type="bullet">
///         <item><c>scope</c>: Duende emits one claim per scope (JSON array for multiple values);
///             OpenIddict emits a single space-delimited string per RFC 9068. The platform's
///             authorization policies (<c>RequireClaim(scope, …)</c> in every service) compare
///             full claim values, so the space-delimited form would break ALL scope checks.</item>
///         <item><c>sub</c> on <c>client_credentials</c> tokens: Duende omits it, and the
///             platform's <c>TenantAuthorizationMiddleware</c> uses the ABSENCE of <c>sub</c> to
///             recognize service-to-service tokens (they bypass the allowed_tenants gate). An
///             OpenIddict-default <c>sub=client_id</c> would lock every adapter out.</item>
///         <item>OpenIddict private claims (<c>oi_*</c>) are stripped — Duende tokens never
///             carried them.</item>
///         <item>Access tokens get no server-side token entry: they are stateless signed JWTs
///             (no reference tokens anywhere on the platform, Duende parity) — persisting an
///             entry per issued token would add a MongoDB write to every token request.</item>
///     </list>
///     Refresh tokens, authorization codes and device/user codes are untouched (they need their
///     entries for redemption/revocation).
/// </summary>
public class OctoAccessTokenShapeHandler : IOpenIddictServerHandler<GenerateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; }
        = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
            .UseSingletonHandler<OctoAccessTokenShapeHandler>()
            .SetOrder(OpenIddictServerHandlers.Protection.GenerateIdentityModelToken.Descriptor.Order - 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(GenerateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // GenerateTokenContext reports the RFC 8693 token type identifier (URN form).
        if (context.TokenType is "urn:ietf:params:oauth:token-type:id_token" or "id_token")
        {
            // Duende parity: id tokens carry no azp (aud == authorized party for our clients)
            // and no OpenIddict-internal private claims.
            var idTokenDescriptor = context.SecurityTokenDescriptor;
            if (idTokenDescriptor?.Claims != null)
            {
                idTokenDescriptor.Claims.Remove(Claims.AuthorizedParty);
                foreach (var key in idTokenDescriptor.Claims.Keys
                             .Where(k => k.StartsWith("oi_", StringComparison.Ordinal)).ToList())
                {
                    idTokenDescriptor.Claims.Remove(key);
                }
            }

            if (idTokenDescriptor?.Subject != null)
            {
                foreach (var claim in idTokenDescriptor.Subject.Claims
                             .Where(c => c.Type == Claims.AuthorizedParty ||
                                         c.Type.StartsWith("oi_", StringComparison.Ordinal)).ToList())
                {
                    idTokenDescriptor.Subject.TryRemoveClaim(claim);
                }
            }

            // Duende parity: id tokens carry an nbf claim as well.
            if (idTokenDescriptor != null)
            {
                idTokenDescriptor.NotBefore ??= DateTime.UtcNow;
            }

            return default;
        }

        if (context.TokenType is not (TokenTypeIdentifiers.AccessToken or TokenTypeHints.AccessToken))
        {
            return default;
        }

        // Stateless JWT access tokens — no per-token database entry (Duende parity).
        context.CreateTokenEntry = false;
        context.PersistTokenPayload = false;

        var descriptor = context.SecurityTokenDescriptor;

        if (descriptor?.Claims != null)
        {
            // Duende parity: one scope claim per value (JSON array), not a space-joined string.
            if (descriptor.Claims.TryGetValue(Claims.Scope, out var scopeValue) &&
                scopeValue is string scopeString && scopeString.Contains(' '))
            {
                descriptor.Claims[Claims.Scope] =
                    scopeString.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
            }

            // Duende parity: client_credentials access tokens carry no sub claim — the platform's
            // TenantAuthorizationMiddleware identifies service-to-service tokens by its absence.
            if (context.Request?.IsClientCredentialsGrantType() == true)
            {
                descriptor.Claims.Remove(Claims.Subject);
            }

            // Strip OpenIddict-internal private claims — Duende tokens never carried them.
            foreach (var key in descriptor.Claims.Keys
                         .Where(k => k.StartsWith("oi_", StringComparison.Ordinal)).ToList())
            {
                descriptor.Claims.Remove(key);
            }
        }

        if (descriptor?.Subject != null)
        {
            if (context.Request?.IsClientCredentialsGrantType() == true)
            {
                descriptor.Subject.TryRemoveClaim(descriptor.Subject.FindFirst(Claims.Subject));
            }

            foreach (var claim in descriptor.Subject.Claims
                         .Where(c => c.Type.StartsWith("oi_", StringComparison.Ordinal)).ToList())
            {
                descriptor.Subject.TryRemoveClaim(claim);
            }
        }

        // Duende parity: access tokens carry an nbf claim (OpenIddict omits it by default).
        if (descriptor != null)
        {
            descriptor.NotBefore ??= DateTime.UtcNow;
        }

        return default;
    }
}
