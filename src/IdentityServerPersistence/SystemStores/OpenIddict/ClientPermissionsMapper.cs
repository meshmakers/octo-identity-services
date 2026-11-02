using System.Collections.Immutable;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     Pure one-way transform from the legacy <see cref="RtClient" /> configuration shape
///     (<c>AllowedGrantTypes</c>, <c>AllowedScopes</c>, flags) to OpenIddict's permissions and
///     requirements model (AB#4991). The stored client data does NOT change — the transform runs
///     at read time inside <see cref="OpenIddictApplicationStore" />.
/// </summary>
/// <remarks>
///     Mapping rules (see docs/CONCEPT-OPENIDDICT-MIGRATION.md §4.3):
///     <list type="bullet">
///         <item><c>authorization_code</c> → authorization code grant + <c>code</c> response type
///             + authorize/token/PAR/end-session endpoints.</item>
///         <item><c>client_credentials</c> → client credentials grant + token endpoint.</item>
///         <item><c>urn:ietf:params:oauth:grant-type:device_code</c> → device code grant +
///             device authorization/token endpoints.</item>
///         <item><c>urn:ietf:params:oauth:grant-type:token-exchange</c> → token exchange grant +
///             token endpoint (native OpenIddict flow since 7.0, AB#4992).</item>
///         <item><c>AllowOfflineAccess</c> → refresh token grant.</item>
///         <item>every entry of <c>AllowedScopes</c> → scope permission
///             (<c>scp:&lt;name&gt;</c>).</item>
///         <item><c>RequirePkce</c> → PKCE requirement.</item>
///     </list>
///     Revocation is permitted for every client (/connect/revocation has always been open to all
///     authenticated clients on this platform). Introspection stays with API-resource secrets and
///     is NOT granted to clients — /connect/introspect authenticates API resources, as before the
///     migration.
/// </remarks>
public static class ClientPermissionsMapper
{
    public const string DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code";
    public const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>The OctoMesh delegation ("on-behalf-of") grant type URN (AB#5026).</summary>
    public const string OnBehalfOfGrantType = "urn:meshmakers:params:oauth:grant-type:on-behalf-of";

    /// <summary>
    ///     The OctoMesh impersonation grant type URN (AB#5114). Own URN, own per-client opt-in:
    ///     becoming another client outright is a strictly stronger capability than delegating or
    ///     exchanging, so it must never ride along on another grant's permission. The
    ///     communication reconcile grants it to adapter clients; anything else is an explicit
    ///     operator decision.
    /// </summary>
    public const string ImpersonationGrantType = "urn:meshmakers:params:oauth:grant-type:impersonate";

    /// <summary>Computes the OpenIddict permission set for a client.</summary>
    public static ImmutableArray<string> MapPermissions(RtClient client)
    {
        var permissions = ImmutableArray.CreateBuilder<string>();

        var grantTypes = client.AllowedGrantTypes?.ToList() ?? [];
        var usesTokenEndpoint = false;

        if (grantTypes.Contains(GrantTypes.AuthorizationCode))
        {
            permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            permissions.Add(Permissions.ResponseTypes.Code);
            permissions.Add(Permissions.Endpoints.Authorization);
            permissions.Add(Permissions.Endpoints.PushedAuthorization);
            permissions.Add(Permissions.Endpoints.EndSession);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(GrantTypes.ClientCredentials))
        {
            permissions.Add(Permissions.GrantTypes.ClientCredentials);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(DeviceCodeGrantType))
        {
            permissions.Add(Permissions.GrantTypes.DeviceCode);
            permissions.Add(Permissions.Endpoints.DeviceAuthorization);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(TokenExchangeGrantType))
        {
            permissions.Add(Permissions.GrantTypes.TokenExchange);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(OnBehalfOfGrantType))
        {
            // Custom flow (AB#5026): OpenIddict models non-built-in grants as prefixed permissions.
            permissions.Add(Permissions.Prefixes.GrantType + OnBehalfOfGrantType);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(ImpersonationGrantType))
        {
            // Custom flow (AB#5114): same prefixed-permission model as on-behalf-of.
            permissions.Add(Permissions.Prefixes.GrantType + ImpersonationGrantType);
            usesTokenEndpoint = true;
        }

        // The stored client configuration models refresh tokens via AllowOfflineAccess; a
        // "refresh_token" entry in AllowedGrantTypes is a legacy variant that is also honored.
        if (client.AllowOfflineAccess || grantTypes.Contains(GrantTypes.RefreshToken))
        {
            permissions.Add(Permissions.GrantTypes.RefreshToken);
            usesTokenEndpoint = true;
        }

        if (usesTokenEndpoint)
        {
            permissions.Add(Permissions.Endpoints.Token);
        }

        // Token revocation is available to every authenticated client (pre-migration behavior
        // consumers rely on).
        permissions.Add(Permissions.Endpoints.Revocation);

        foreach (var scope in client.AllowedScopes ?? Enumerable.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(scope))
            {
                permissions.Add(Permissions.Prefixes.Scope + scope);
            }
        }

        return permissions.Distinct(StringComparer.Ordinal).ToImmutableArray();
    }

    /// <summary>
    ///     Every grant type <see cref="MapPermissions" /> understands. An entry in a client's
    ///     <c>AllowedGrantTypes</c> outside this set contributes NOTHING to the permission set —
    ///     which is the failure mode AB#5266 was: <c>implicit</c> (dropped with the move to
    ///     OpenIddict, AB#4989) left <c>octo-reportingServices</c> and <c>octo-botServices</c>
    ///     without a response type and without the authorize / PAR / token endpoints, so every
    ///     interactive login died before any application code ran. Keep in step with the
    ///     <c>grantTypes.Contains(...)</c> branches above — <see cref="GetUnsupportedGrantTypes" />
    ///     is what turns a future omission into a log line instead of a silent outage.
    /// </summary>
    public static readonly ImmutableHashSet<string> SupportedGrantTypes =
    [
        GrantTypes.AuthorizationCode,
        GrantTypes.ClientCredentials,
        GrantTypes.RefreshToken,
        DeviceCodeGrantType,
        TokenExchangeGrantType,
        OnBehalfOfGrantType,
        ImpersonationGrantType
    ];

    /// <summary>
    ///     The client's stored grant types that this transform does not map, in stored order and
    ///     de-duplicated. Empty for every well-formed client. Diagnostic only — the transform
    ///     itself stays total and non-throwing, because refusing to project a client would take
    ///     the whole tenant's token endpoint down rather than the one misconfigured client.
    /// </summary>
    public static ImmutableArray<string> GetUnsupportedGrantTypes(RtClient client)
    {
        if (client.AllowedGrantTypes is null)
        {
            return ImmutableArray<string>.Empty;
        }

        return
        [
            .. client.AllowedGrantTypes
                .Where(grantType => !string.IsNullOrWhiteSpace(grantType))
                .Where(grantType => !SupportedGrantTypes.Contains(grantType))
                .Distinct(StringComparer.Ordinal)
        ];
    }

    /// <summary>
    ///     True when the computed permission set authorizes no OAuth flow at all, i.e. the client
    ///     cannot obtain a token by any means. Always a misconfiguration: a client in this state
    ///     answers every authorize, PAR and token request with a protocol error that names the
    ///     request, never the client — which is exactly why AB#5266 took so long to place.
    /// </summary>
    public static bool GrantsNoFlow(ImmutableArray<string> permissions)
        => !permissions.Any(permission =>
            permission.StartsWith(Permissions.Prefixes.GrantType, StringComparison.Ordinal));

    /// <summary>Computes the OpenIddict requirement set for a client.</summary>
    public static ImmutableArray<string> MapRequirements(RtClient client)
    {
        return client.RequirePkce
            ? [Requirements.Features.ProofKeyForCodeExchange]
            : ImmutableArray<string>.Empty;
    }
}
